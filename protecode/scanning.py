import logging
import typing

import cnudie.retrieve
import cnudie.util
import gci.componentmodel as cm
import protecode.client
import protecode.model as pm
import protecode.util

from protecode.client import ProtecodeApi


logger = logging.getLogger(__name__)


class ResourceGroupProcessor:
    def __init__(
        self,
        component_descriptor: cm.ComponentDescriptor, # will not be needed after changes to ResourceGroup element
        protecode_api: ProtecodeApi,
        group_id: int=None,
        reference_group_ids: typing.Sequence[int]=(),
    ):
        self.component_descriptor = component_descriptor
        self.protecode_api = protecode_api
        self.group_id = group_id
        self.reference_group_ids = reference_group_ids

    def generate_jobs(self, resource_group: pm.ResourceGroup) -> typing.Iterator[pm.Job]: pass

    def scans_with_relevant_triages(
        self,
        jobs: typing.Iterable[pm.Job],
    ):
        # We can use any job as prototype since we'll be interested in meta-data that is version
        # agnostic
        job: pm.Job = jobs[0]
        for id in self.reference_group_ids: # TODO: Also consider own group
            yield from self.protecode_api.list_apps(
                id,
                job.metadata(omit_resource_version=True),
            )

    def process_job(
        self,
        job: pm.Job,
        processing_mode: pm.ProcessingMode,
    ) -> pm.AnalysisResult:
        # since we always upload all the available metadata, we can prepare it in advance
        metadata = job.metadata(
            omit_resource_version=False,
        )
        # TODO: functools.partial for the upload-func?
        if processing_mode is pm.ProcessingMode.FORCE_UPLOAD:
            if (job_id := job.product_id):
                # reupload binary
                return self.protecode_api.upload(
                    application_name=job.display_name(),
                    group_id=self.group_id,
                    data=job.binary.upload_data(),
                    replace_id=job_id,
                    custom_attribs=metadata,
                )
            else:
                # upload new product
                return self.protecode_api.upload(
                    application_name=job.display_name(),
                    group_id=self.group_id,
                    data=job.binary.upload_data(),
                    custom_attribs=metadata,
                )
        elif processing_mode is pm.ProcessingMode.RESCAN:
            if (job_id := job.product_id):
                # check if result can be reused
                scan_result = self.protecode_api.scan_result_short(product_id=job_id)
                if scan_result.is_stale() and not scan_result.has_binary():
                    # no choice but to upload
                    # TODO check whether scans can be non-stale without binary
                    return self.protecode_api.upload(
                        application_name=job.display_name(),
                        group_id=self.group_id,
                        data=job.binary.upload_data(),
                        replace_id=job_id,
                        custom_attribs=metadata,
                    )
                # update name/metadata in any case
                self.protecode_api.set_product_name(product_id=job_id, name=job.display_name())
                self.protecode_api.set_metadata(product_id=job_id, custom_attribs=metadata)

                if not scan_result.is_stale():
                    pass # no special handling required
                if scan_result.has_binary():
                    # binary is still available, trigger rescan
                    self.protecode_api.rescan(product_id=job_id)
                return self.protecode_api.scan_result(product_id=job_id)
            else:
                return self.protecode_api.upload(
                    application_name=job.display_name(),
                    group_id=self.group_id,
                    data=job.binary.upload_data(),
                    custom_attribs=metadata,
                )
        else:
            raise NotImplementedError(processing_mode)

    def process(
        self,
        resource_group: pm.ResourceGroup,
        processing_mode: pm.ProcessingMode,
    ) -> typing.Iterator(pm.AnalysisResult):
        logger.info(f'Processing ResourceGroup {resource_group}')

        jobs_to_process = list(self.generate_jobs(resource_group))

        scans = protecode.util.wait_for_scans_to_finish(
            scans=(
                self.process_job(job=job, processing_mode=processing_mode)
                for job in jobs_to_process
            ),
            protecode_api=self.protecode_api,
        )
        # _do_ the actual processing/waiting
        scans = list(scans)

        # fetch all relevant scans from all reference protecode groups
        scans_with_triages = list(self.scans_with_relevant_triages(jobs_to_process))

        logger.info(
            f'found {len(scans_with_triages)} scans with relevant triages to import for resource '
            f' group {resource_group}.'
        )

        # also consider new scans for triage-transport.
        scans_with_triages.extend(scans)

        protecode.util.copy_triages(
            from_results=scans_with_triages,
            to_results=scans,
            to_group_id=self.group_id,
            protecode_api=self.protecode_api,
        )

        yield from scans

        # self._delete_outdated_protecode_apps()

    # TODO: (Is this/should this be) instance-specific?
    def _find_product_id_for_job(
        self,
        job: pm.Job,
        protecode_group_id: int,
    ) -> int | None:
        apps = self.protecode_api.list_apps(
            group_id=protecode_group_id,
            custom_attribs=job.metadata(
                omit_resource_version=False,
            ),
        )
        if (known_apps := len(apps)) == 0:
            return None

        if known_apps >= 1:
            # TODO: Delete duplicate Scans as we did before?
            raise RuntimeError()

        return apps[0].product_id()


def _find_scan_results(
    protecode_client: protecode.client.ProtecodeApi,
    group_id: int,
    artifact_groups: typing.Iterable[pm.ArtifactGroup],
) -> typing.Dict[str, pm.AnalysisResult]:
    scan_results = dict()
    for artifact_group in artifact_groups:
        match artifact_group:
            case pm.OciArtifactGroup():
                # prepare prototypical metadata for the artifact group, i.e. without any version information
                prototype_metadata = protecode.util.component_artifact_metadata(
                    artifact_group=artifact_group.component_artifacts[0],
                    omit_component_version=True,
                    omit_resource_version=True,
                )
            case pm.TarRootfsArtifactGroup():
                prototype_metadata = protecode.util.component_artifact_metadata(
                    artifact_group=artifact_group.component_artifacts[0],
                    omit_component_version=False,
                    omit_resource_version=True,
                )
        scans = list(protecode_client.list_apps(
            group_id=group_id,
            custom_attribs=prototype_metadata,
        ))
        scan_results[artifact_group.name] = scans

    return scan_results


def _scan_requests(
    artifact_groups: typing.Iterable[pm.ArtifactGroup],
    known_artifact_scans: typing.Dict[str, pm.AnalysisResult]
) -> typing.Iterable[pm.ScanRequest]:
    for artifact_group in artifact_groups:
        match artifact_group:
            case pm.OciArtifactGroup():
                # generate one ScanRequest for each ComponentArtifact
                yield from (
                    pm.ScanRequest(
                        scan_content=pm.OciResourceBinary(component_artifact.artifact),
                        display_name=artifact_group.name,
                        target_product_id=known_artifact_scans.get(artifact_group.name),
                        custom_metadata=protecode.util.component_artifact_metadata(
                            component_artifact=component_artifact,
                            omit_component_version=False,
                            omit_resource_version=False,
                        )
                    )
                    for component_artifact in artifact_groups.component_artifacts
                )
            case pm.TarRootfsArtifactGroup():
                # Generate one ScanRequest for all ComponentArtifacts. For this kind of ArtifactGroup
                # we merge all appropriate (tar)artifacts into one big tararchive
                yield pm.ScanRequest(
                    binary=pm.TarRootfsAggregateResourceBinary(
                        resources = [a.artifact for a in artifact_group.component_artifacts]
                    ),
                    display_name=artifact_group.name,
                    target_product_id=known_artifact_scans.get(artifact_group.name),
                    custom_metadata=protecode.util.component_artifact_metadata(
                            # All components have the same version so we can use any
                            # ComponentArtifacts for the metadata-calculation.
                            component_artifact=artifact_group.component_artifacts[0],
                            omit_component_version=False,
                            omit_resource_version=False,
                        ),
                )
            case _:
                raise NotImplementedError(artifact_group)

class OciResourceGroupProcessor(ResourceGroupProcessor):
    # TODO: move to top level and create dispatcher function
    def _generate_jobs(
        self,
        resource_group: pm.ResourceGroup,
    ) -> typing.Iterator[pm.ScanRequest]:
        # For OciResourceGroups we need to generate one Job for each instance of the
        # given resource that is part of any instance of the given Component
        filtered_components = filter(
            lambda c: c.name == resource_group.component_name,
            list(cnudie.retrieve.components(component=self.component_descriptor))
        )
        # iterate over all resources and create Jobs
        jobs = [
            pm.Job(component_name=resource_group.component_name, binary=pm.OciResourceBinary(r))
            for c in filtered_components
            for r in c.resources
            if r.name == resource_group.resource_name
        ]
        # find and set IDs for previous scans, if possible
        # TODO: Could be handled by superclass
        for j in jobs:
            # Replace with lookup via struct/dataclass
            j.product_id = self._find_product_id_for_job(
                job=j,
                protecode_group_id=self.group_id,
            )
        yield from jobs

class TarRootfsResourceGroupProcessor(ResourceGroupProcessor):
    def generate_jobs(
        self,
        resource_group: pm.TarRootfsResourceGroup,
    ) -> typing.Iterator[pm.Job]:
        filtered_components = (
            c for c in list(cnudie.retrieve.components(component=self.component_descriptor))
            if c.name == resource_group.component_name and c.version == resource_group.component_version
        )
        # There should be exactly one component
        if not (component := next(filtered_components, None)):
            raise RuntimeError(
                f"No component for resource group '{resource_group}'"
            )
        if next_component := next(filtered_components, None):
            raise RuntimeError(
                f"More than one component for resource group '{resource_group}': {next_component}"
            )

        rootfs_resource_type = 'application/tar+vm-image-rootfs'
        rootfs_resources = [
            r
            for r in component.resources
            if r.type == rootfs_resource_type
        ]
        if len(rootfs_resources) == 0:
            raise RuntimeError(
                f"No resources of type '{rootfs_resource_type}' in component '{component}'"
            )
        job = pm.Job(
            binary=pm.TarRootfsAggregateResourceBinary(rootfs_resources),
            component_name=resource_group.component_name,
        )
        job.product_id = self._find_product_id_for_job(
            job=job,
            protecode_group_id=self.group_id,
        )
        yield job
