from concurrent.futures import ThreadPoolExecutor
import logging
import boto3
import botocore
import botocore.client
import tarfile
import io
import typing
import os.path
import os
import copy
import collections

import ccc.aws
import ccc.delivery
import ccc.gcp
import ccc.protecode
import cnudie.retrieve
import cnudie.util
import protecode.model as pm
import protecode.client
from protecode.scanning_util import ProcessingMode

import gci.componentmodel as cm


logger = logging.getLogger(__name__)

# TODO: Hmmmm....
GARDENLINUX_COMPONENT_NAME = 'github.com/gardenlinux/gardenlinux'
GARDENLINUX_ROOTFS_TAR_RESOURCE_TYPE = 'application/tar+vm-image-rootfs'


def _enum_triages(
    result: pm.AnalysisResult
) -> typing.Iterator[typing.Tuple[pm.Component, pm.Triage]]:
    for component in result.components():
        for vulnerability in component.vulnerabilities():
            for triage in vulnerability.triages():
                yield component, triage


def _enum_component_versions(
    scan_result: pm.AnalysisResult,
    component_name: str,
) -> typing.Iterator[str]:
    for component in scan_result.components():
        if component.name() == component_name:
            yield component.version()


def copy_triages( # TODO: move to protecode.util; from_group_id
    from_results: typing.Iterable[pm.AnalysisResult],
    to_result: pm.AnalysisResult, # TODO: support iterable
    to_group_id: int,
    protecode_api,
):
    '''Copy triages from a number of scan results to a single result.

    Copied triages are deduplicated.
    '''

    to_component_versions = {
        component.name(): list(_enum_component_versions(to_result, component.name()))
        for component in to_result.components()
    }

    from_triages = collections.defaultdict(set)
    for result in from_results:
        for component, triage in _enum_triages(result):
            from_triages[component.name()].add(triage)

    for component_name in from_triages:
        for triage in from_triages[component_name]:
            for component_version in to_component_versions[component_name]:
                protecode_api.add_triage(
                    triage=triage,
                    product_id=to_result.product_id(),
                    group_id=to_group_id,
                    component_version=component_version,
                )


def custom_metadata(
    component: cm.Component = None,
) -> dict[str, str]:
    metadata = {
        'NAME': GARDENLINUX_COMPONENT_NAME,
    }
    if component:
        metadata.update({'VERSION': component.version})
    return metadata


def upload_name(
        component: cm.Component,
    ):
        return f'{component.name}_{component.version}'.replace('/', '_')


def wait_for_scans_to_finish(
    protecode_client: protecode.client.ProtecodeApi,
    scans: typing.Iterable[pm.AnalysisResult],
) -> typing.Generator[pm.ProcessingStatus, None, None]:
    for scan_result in scans:
        product_id = scan_result.product_id()
        logger.info(f'waiting for {product_id}')
        yield protecode_client.wait_for_scan_result(product_id)
        logger.info(f'finished waiting for {product_id}')


def process(
    protecode_cfg_name: str,
    component_descriptor: cm.ComponentDescriptor,
    protecode_group_id: int,
    parallel_jobs: int,
    processing_mode: ProcessingMode = ProcessingMode.FORCE_UPLOAD,
) -> typing.Iterable[pm.AnalysisResult]:
    protecode_client = ccc.protecode.client_from_config_name(protecode_cfg_name)
    components = list(cnudie.retrieve.components(component=component_descriptor))

    gardenlinux_components = [
        component
        for component in components
        if component.name == GARDENLINUX_COMPONENT_NAME
    ]
    # TODO: rm
    gardenlinux_components = gardenlinux_components[:1]

    existing_results = {
        r.custom_data()['VERSION']:r
        for r in protecode_client.list_apps(
            group_id=protecode_group_id,
            custom_attribs=custom_metadata(),
        )
    }

    # determine scans to (re)upload
    gardenlinux_versions = [component.version for component in gardenlinux_components]

    # TODO: Make components hashable.
    # Once components are hashable, simplify to dict[component, AnalysisResult]
    gardenlinux_components_with_scans = {
        component.name: (component, existing_results[component.version])
        for component in gardenlinux_components
        if component.version in existing_results
    }

    gardenlinux_components_without_scans = [
        component
        for component in gardenlinux_components
        if component.name not in gardenlinux_components_with_scans
    ]

    results_of_removed_gardenlinux_versions = [
        result
        for version, result in existing_results.items()
        if version not in gardenlinux_versions
    ]

    pool = ThreadPoolExecutor(max_workers=parallel_jobs)

    if processing_mode in [ProcessingMode.FORCE_UPLOAD, ProcessingMode.RESCAN]:
        futures = [
            pool.submit(
                process_component,
                protecode_client=protecode_client,
                gardenlinux_component=component,
                protecode_group_id=protecode_group_id,
                processing_mode=processing_mode,
            ) for component in gardenlinux_components_without_scans
        ] + [
            pool.submit(
                process_component,
                protecode_client=protecode_client,
                gardenlinux_component=component,
                replace_id=result.product_id(),
                processing_mode = processing_mode,
                protecode_group_id=protecode_group_id,
            ) for _, (component, result) in gardenlinux_components_with_scans.items()
        ]
        scans = [f.result() for f in futures]

    else:
        raise NotImplementedError(processing_mode)

    scan_results = list(wait_for_scans_to_finish(
        protecode_client=protecode_client,
        scans=scans,
    ))

    # copy triages
    for result in scan_results:
        copy_triages(
            from_results=list(existing_results.values()),
            to_result=result,
            to_group_id=protecode_group_id,
            protecode_api=protecode_client,
        )

    # delete removed versions
    # for p in results_of_removed_gardenlinux_versions:
    #     protecode_client.delete_product(p.product_id())

    return scan_results


def _read_s3_fileobj(
    resource: cm.Resource,
):
    access: cm.S3Access = resource.access
    s3_client = boto3.client(
        's3',
        config=botocore.client.Config(signature_version=botocore.UNSIGNED)
    )
    s3_object = s3_client.get_object(Bucket=access.bucketName, Key=access.objectKey)
    return s3_object['Body']


def write_combined_tarfile(
        output_file: io.IOBase,
        gardenlinux_component: cm.Component,
    ):
        '''Write a tar file created from all rootfs-tarfiles of the given Gardenlinux component to
        the given file-like object

        When adding a new file, it is first checked whether the file is already part of the archive.
        This results in one of three outcomes:

        1. The file is not present in the archive. It is then simply added.
        2. The file is already present in the archive at least once, but the new instance differs
            in size from all other variants contained in the archive. It is then added to the archive
            (with unique prefix if it was already present with different size).
        3. The file is already present in the exact same size. Here it is assumed that the file is
            identical to the one already present and it is not added again.

        This reduces the size of files that have to be scanned by protecode.
        '''
        def process_tarinfo(
            tar_info: tarfile.TarInfo,
            known_tar_sizes: collections.defaultdict[str, set[int]],
            prefix: str,
        ) -> tarfile.TarInfo | None:
            if not tar_info.isfile():
                return

            file_name = tar_info.name
            if any((size == tar_info.size for size in known_tar_sizes[file_name])):
                # we already have seen a file with the same name and size
                return

            known_tar_sizes[file_name].add(tar_info.size)
            # TODO: The way this is done preserves the structure of the first tar-archive
            # processed. Consider simply prefixing all files.
            if len(known_tar_sizes[file_name]) == 0:
                # never seen this file, simply return original tarinfo
                return tar_info
            else:
                # file was already added (with differenz size). Prefix filename to avoid collision
                mod_filename = os.path.join(prefix, file_name)
                mod_tar_info = copy.deepcopy(tar_info)
                mod_tar_info.name = mod_filename
                return mod_tar_info

        rootfs_resources = [
            resource
            for resource in gardenlinux_component.resources
            if resource.type == GARDENLINUX_ROOTFS_TAR_RESOURCE_TYPE
        ]
        rootfs_resources = rootfs_resources[:2]
        with tarfile.open(fileobj=output_file, mode='w:gz') as combined_archive:
            known_tar_sizes = collections.defaultdict(set)
            for resource in rootfs_resources:
                with tarfile.open(fileobj=_read_s3_fileobj(resource), mode='r|*') as tar_archive:
                    for tar_info in tar_archive:
                        if processed_tar_info := process_tarinfo(
                            tar_info=tar_info,
                            known_tar_sizes=known_tar_sizes,
                            prefix=resource.extraIdentity['platform'],
                        ):
                            combined_archive.addfile(
                                tarinfo=processed_tar_info,
                                fileobj=tar_archive.extractfile(tar_info),
                            )


def process_component(
    protecode_client: protecode.client.ProtecodeApi,
    gardenlinux_component: cm.Component,
    protecode_group_id: int,
    processing_mode: ProcessingMode,
    replace_id: int = None,
):
    if replace_id and processing_mode is ProcessingMode.RESCAN:
        scan_result_short = protecode_client.scan_result_short(product_id=replace_id)
        if not scan_result_short.is_stale():
            return protecode_client.scan_result(product_id=replace_id)
        if scan_result_short.has_binary():
            protecode_client.rescan(product_id=replace_id)
            return protecode_client.scan_result(product_id=replace_id)

    with io.BytesIO() as filelike_obj:
        write_combined_tarfile(
            output_file=filelike_obj,
            gardenlinux_component=gardenlinux_component,
        )
        filelike_obj.seek(0)
        return protecode_client.upload(
            application_name=upload_name(gardenlinux_component),
            group_id=protecode_group_id,
            replace_id=replace_id,
            data=filelike_obj,
            custom_attribs=custom_metadata(gardenlinux_component),
        )
