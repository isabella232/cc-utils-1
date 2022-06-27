from collections.abc import (
    Sequence,
)
import logging

import cnudie.util
import cnudie.retrieve
import protecode.model as pm
import gci.componentmodel as cm

from protecode.client import ProtecodeApi
from ci.util import not_none, warning, check_type, info


logger = logging.getLogger(__name__)


class ResourceGroupProcessor:
    def __init__(
        self,
        component_descriptor,
        resource_group,
        protecode_api: ProtecodeApi,
        processing_mode: pm.ProcessingMode=pm.ProcessingMode.RESCAN,
        group_id: int=None,
        reference_group_ids: Sequence[int]=(),
    ):
        self.component_descriptor = component_descriptor
        self.resource_group = resource_group
        self.protecode_api = protecode_api
        self.processing_mode = processing_mode
        self.group_id = group_id
        self.reference_group_ids = reference_group_ids

    def process(
        self
    ):
        logger.info(f'Processing ResourceGroup {self.resource_group}')

        self._prepare()

        existing_scans = self._find_existing_scans()

        # Need a class to represent the scan that is to happen - ProtecodeJob?

        if self._processing_mode is pm.ProcessingMode.FORCE_UPLOAD:
            pass
        elif self._processing_mode is pm.ProcessingMode.RESCAN:
            pass
        else:
            raise NotImplementedError()


        # trigger rescan if recommended for all protecode apps
        self._trigger_rescan_if_recommended()

        self._import_triages()
        self._copy_triages()

        # yield results

        self._delete_outdated_protecode_apps()

class OciResourceGroupProcessor(ResourceGroupProcessor):

    def generate_jobs(
        self,
        component_descriptor: cm.ComponentDescriptor,
        resource_group: pm.OciResourceGroup,
    ):
        components = list(filter(
            lambda c: c.name == resource_group.component_name,
            list(cnudie.retrieve.components(component=component_descriptor))
        ))
        resources = [
            r
            for c in components
            for r in c.resources
            if r.name == resource_group.resource_name
        ]
        yield from (
            pm.ProtecodeScan(
                binary=pm.Binary(r)
            ) for r in resources
        )

