# Copyright (c) 2019-2020 SAP SE or an SAP affiliate company. All rights reserved. This file is
# licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
from concurrent.futures import ThreadPoolExecutor
import datetime
import logging
import tabulate
import typing

import ccc.delivery
import ccc.gcp
import ccc.protecode
import cnudie.retrieve
import cnudie.util
import dso.model
import product.util
import product.v2
import protecode.model as pm

import gci.componentmodel as cm

from protecode.scanning_util import (
    ProcessingMode,
    ProtecodeProcessor
)
from protecode.model import (
    CVSSVersion,
)

logger = logging.getLogger(__name__)


def upload_grouped_images(
    protecode_cfg,
    component_descriptor,
    protecode_group_id=5,
    parallel_jobs=8,
    cve_threshold=7,
    ignore_if_triaged=True,
    processing_mode=ProcessingMode.RESCAN,
    image_reference_filter=(lambda component, resource: True),
    reference_group_ids=(),
    cvss_version=CVSSVersion.V3,
) -> tuple[
    typing.Sequence[pm.BDBA_ScanResult],
]:
    executor = ThreadPoolExecutor(max_workers=parallel_jobs)
    protecode_api = ccc.protecode.client(protecode_cfg)
    protecode_api.set_maximum_concurrent_connections(parallel_jobs)
    protecode_api.login()

    def _upload_task(component_resources):
        def _task():
            # force executor to actually iterate through generator
            protecode_processor = ProtecodeProcessor(
                component_resources=component_resources,
                protecode_api=protecode_api,
                processing_mode=processing_mode,
                group_id=protecode_group_id,
                reference_group_ids=reference_group_ids,
                cvss_threshold=cve_threshold,
            )
            return tuple(protecode_processor.process_component_resources())

        return _task

    def _upload_tasks():
        # group images of same name w/ different versions
        component_groups = collections.defaultdict(list)
        components = list(cnudie.retrieve.components(component=component_descriptor))

        for component in components:
            component_groups[component.name].append(component)

        def group_by_resource_name(
            components
        ) -> typing.Generator[
            list[cnudie.util.ComponentResource],
            None,
            None
        ]:
            # groups resources of components by resource name
            resource_groups = collections.defaultdict(list[cnudie.util.ComponentResource])
            for component in components:
                # TODO: Handle other resource types
                for resource in product.v2.resources(
                    component=component,
                    resource_types=[cm.ResourceType.OCI_IMAGE],
                    resource_access_types=[cm.AccessType.OCI_REGISTRY],
                ):
                    resource_groups[resource.name].append(
                        cnudie.util.ComponentResource(
                            component=component,
                            resource=resource,
                        )
                    )

            yield from resource_groups.values()

        for components in component_groups.values():
            for component_resources in group_by_resource_name(components):
                # all components in a component group share a name
                component_resources = [
                    r for r in component_resources if image_reference_filter(component, r.resource)
                ]

                if component_resources:
                    yield _upload_task(component_resources=component_resources)

    tasks = _upload_tasks()
    results = tuple(executor.map(lambda task: task(), tasks))

    def flatten_results():
        for result_set in results:
            yield from result_set

    results = tuple(flatten_results())

    if (delivery_client := ccc.delivery.default_client_if_available()):
        logger.info('uploading results to deliverydb')
        try:
            for artefact_metadata in iter_artefact_metadata(results):
                delivery_client.upload_metadata(data=artefact_metadata)
        except:
            import traceback
            traceback.print_exc()

    else:
        logger.warning('not uploading results to deliverydb, client not available')

    return results


def filter_and_display_upload_results(
    upload_results: typing.Sequence[pm.BDBA_ScanResult],
    cvss_version: CVSSVersion,
    cve_threshold=7,
    ignore_if_triaged=True,
) -> typing.Sequence[pm.BDBA_ScanResult]:
    # we only require the analysis_results for now

    results_without_components = []
    results_below_cve_thresh = []
    results_above_cve_thresh = []

    for upload_result in upload_results:
        resource = upload_result.artifact

        if isinstance(upload_result, pm.BDBA_ScanResult):
            result = upload_result.result
        else:
            result = upload_result

        components = result.components()
        if not components:
            results_without_components.append(upload_result)
            continue

        greatest_cve = upload_result.greatest_cve_score

        if greatest_cve >= cve_threshold:
            try:
                # XXX HACK: just any image ref from group
                image_ref = resource.access.imageReference
                grafeas_client = ccc.gcp.GrafeasClient.for_image(image_ref)
                gcr_cve = -1
                for r in grafeas_client.filter_vulnerabilities(
                    image_ref,
                    cvss_threshold=cve_threshold,
                ):
                    gcr_cve = max(gcr_cve, r.vulnerability.cvssScore)
                # TODO: skip if < threshold - just report for now
            except Exception:
                import traceback
                logger.warning(
                    f'failed to retrieve vulnerabilies from gcr {traceback.format_exc()}'
                )

            results_above_cve_thresh.append(upload_result)
            continue
        else:
            results_below_cve_thresh.append(upload_result)
            continue

    if results_without_components:
        logger.warning(
            f'Protecode did not identify components for {len(results_without_components)=}:\n'
        )
        for result in results_without_components:
            print(result.result.display_name())
        print('')

    def render_results_table(upload_results: typing.Sequence[pm.BDBA_ScanResult]):
        header = ('Component Name', 'Greatest CVE')
        results = sorted(upload_results, key=lambda e: e.greatest_cve_score)

        def to_result(result):
            if isinstance(result, pm.BDBA_ScanResult):
                return result.result
            return result

        result = tabulate.tabulate(
            [(to_result(r).display_name(), r.greatest_cve_score) for r in results],
            headers=header,
            tablefmt='fancy_grid',
        )
        print(result)

    if results_below_cve_thresh:
        logger.info(f'The following components were below configured cve threshold {cve_threshold}')
        render_results_table(upload_results=results_below_cve_thresh)
        print('')

    if results_above_cve_thresh:
        logger.warning('The following components have critical vulnerabilities:')
        render_results_table(upload_results=results_above_cve_thresh)

    return results_above_cve_thresh, results_below_cve_thresh


def iter_artefact_metadata(
    results: typing.Collection[pm.BDBA_ScanResult],
) -> typing.Generator[dso.model.GreatestCVE, None, None]:
    for result in results:
        artefact_ref = dso.model.component_artefact_id_from_ocm(
            component=result.component,
            artefact=result.artifact,
        )
        meta = dso.model.Metadata(
            datasource=dso.model.Datasource.BDBA,
            type=dso.model.Datatype.VULNERABILITIES_AGGREGATED,
            creation_date=datetime.datetime.now()
        )
        cve = dso.model.GreatestCVE(
            greatestCvss3Score=result.greatest_cve_score,
            reportUrl=result.result.report_url()
        )
        yield dso.model.ArtefactMetadata(
            artefact=artefact_ref,
            meta=meta,
            data=cve,
        )

        meta = dso.model.Metadata(
            datasource=dso.model.Datasource.BDBA,
            type=dso.model.Datatype.LICENSES_AGGREGATED,
            creation_date=datetime.datetime.now()
        )
        license_names = list(dict.fromkeys(
            [
                component.license().name()
                for component in result.result.components()
                if component.license()
            ]
        ))
        license = dso.model.LicenseSummary(
            licenses=license_names,
        )
        yield dso.model.ArtefactMetadata(
            artefact=artefact_ref,
            meta=meta,
            data=license,
        )

        meta = dso.model.Metadata(
            datasource=dso.model.Datasource.BDBA,
            type=dso.model.Datatype.COMPONENTS,
            creation_date=datetime.datetime.now()
        )
        components = list(dict.fromkeys(
            [
                dso.model.ComponentVersion(
                    name=component.name(),
                    version=component.version(),
                )
                for component in result.result.components()
            ]
        ))
        component = dso.model.ComponentSummary(
            components=components
        )
        yield dso.model.ArtefactMetadata(
            artefact=artefact_ref,
            meta=meta,
            data=component,
        )
