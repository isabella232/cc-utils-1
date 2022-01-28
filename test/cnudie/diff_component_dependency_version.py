import unittest
import pytest

import gci.componentmodel as cm

import cnudie.util


def comp(name, version, refs=[]) -> cm.Component:
    return cm.Component(
        name=name,
        version=version,
        provider=cm.Provider.INTERNAL,
        repositoryContexts=[
          cm.OciRepositoryContext(
            'test',
            cm.OciComponentNameMapping.URL_PATH,
            cm.AccessType.OCI_REGISTRY,
          )
        ],
        componentReferences=refs,
        sources=[],
        resources=[],
        labels=[],
    )


def c_ref(name, version) -> cm.ComponentReference:
    return cm.ComponentReference(
      componentName=name,
      name=name,
      version=version,
      extraIdentity={},
      labels=[],
    )


def gen_components() -> dict:
    components = [
        comp('c1', '1.0.0'),
        comp('c1', '2.0.0'),
        comp('c2', '1.0.0'),
        comp('c2', '2.0.0'),
        comp('c2', '3.0.0'),
        comp('c3', '1.0.0'),
        comp('c4', '1.0.0', [c_ref('c5', '1.0.0')]),
        comp('c5', '1.0.0'),
        comp('c5', '2.0.0'),
    ]
    return {f'{c.name}_{c.version}': c for c in components}


def _assert_all(expected, actual):
    assert len(expected) == len(actual)
    assert all([a == b for a,b in zip(expected, actual)])


def cde(parent, left, right) -> cnudie.util.ComponentDiffEntry:
    return cnudie.util.ComponentDiffEntry(parent, left, right)


def resolve_ref(cache_dir, component_name, component_version, ctx_repo):
    c_ids = gen_components()
    return cm.ComponentDescriptor([], c_ids.get(f'{component_name}_{component_version}'))


def test_same_dependency():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')

    right_parent.componentReferences = [c_ref(c2.name, c2.version)]
    left_parent.componentReferences = [c_ref(c2.name, c2.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [cde(None, left_parent, right_parent)]


def test_removed_dependency():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version)]
    right_parent.componentReferences = []
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(left_parent, c2, None),
        cde(None, left_parent, right_parent),
    ]


def test_added_dependency():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = []
    right_parent.componentReferences = [c_ref(c3.name, c3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(right_parent, None, c3),
        cde(None, left_parent, right_parent),
    ]


def test_added_and_removed_dependency():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version)]
    right_parent.componentReferences = [c_ref(c3.name, c3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(left_parent, c2, None),
        cde(right_parent, None, c3),
        cde(None, left_parent, right_parent),
    ]


def test_version_upgrade():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c2_2 = c_ids.get('c2_2.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version)]
    right_parent.componentReferences = [c_ref(c2_2.name, c2_2.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(right_parent, c2, c2_2),
        cde(None, left_parent, right_parent),
    ]


def test_version_downgrade():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c2_2 = c_ids.get('c2_2.0.0')

    left_parent.componentReferences = [c_ref(c2_2.name, c2_2.version)]
    right_parent.componentReferences = [c_ref(c2.name, c2.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(right_parent, c2_2, c2),
        cde(None, left_parent, right_parent),
    ]


def test_two_removed_components():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c3.name, c3.version)]
    right_parent.componentReferences = []
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    _assert_all(
        [
            cde(left_parent, c2, None),
            cde(left_parent, c3, None),
            cde(None, left_parent, right_parent),
        ],
        list(diff),
    )


def test_two_added_components():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = []
    right_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c3.name, c3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(right_parent, None, c2),
        cde(right_parent, None, c3),
        cde(None, left_parent, right_parent),
    ]


def test_removed_and_same_component():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c3.name, c3.version)]
    right_parent.componentReferences = [c_ref(c2.name, c2.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(left_parent, c3, None),
        cde(None, left_parent, right_parent),
    ]


def test_added_and_same_component():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version)]
    right_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c3.name, c3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(right_parent, None, c3),
        cde(None, left_parent, right_parent),
    ]


def test_two_added_same_components():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c3 = c_ids.get('c3_1.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c3.name, c3.version)]
    right_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c3.name, c3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [cde(None, left_parent, right_parent)]


def test_version_upgrade():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c2_2 = c_ids.get('c2_2.0.0')
    c2_3 = c_ids.get('c2_3.0.0')

    left_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c2_2.name, c2_2.version)]
    right_parent.componentReferences = [c_ref(c2_2.name, c2_2.version), c_ref(c2_3.name, c2_3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(right_parent, c2, c2_3),
        cde(None, left_parent, right_parent),
    ]


def test_added_and_removed_components():
    c_ids = gen_components()
    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']
    c2 = c_ids.get('c2_1.0.0')
    c2_2 = c_ids.get('c2_2.0.0')
    c2_3 = c_ids.get('c2_3.0.0')

    # check two added same components with different versions
    left_parent.componentReferences = [c_ref(c2.name, c2.version), c_ref(c2_2.name, c2_2.version)]
    right_parent.componentReferences = [c_ref(c2_3.name, c2_3.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(left_parent, c2_2, None),
        cde(right_parent, c2, c2_3),
        cde(None, left_parent, right_parent),
    ]


def test_something():
    c_ids = gen_components()
    c1_1 = c_ids.get('c1_1.0.0')
    c1_2 = c_ids.get('c1_2.0.0')
    c2 = c_ids.get('c2_1.0.0')
    c2_2 = c_ids.get('c2_2.0.0')
    c2_3 = c_ids.get('c2_3.0.0')
    c3 = c_ids.get('c3_1.0.0')
    c4 = c_ids.get('c4_1.0.0')
    c5 = c_ids.get('c5_1.0.0')

    left_parent = c_ids['c1_1.0.0']
    right_parent = c_ids['c1_2.0.0']

    # check two added components left side one via c ref
    left_parent.componentReferences = [c_ref(c4.name, c4.version)]
    right_parent.componentReferences = []
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        cde(left_parent, c4, None),
        cde(c4,c5,None),
        cde(None, left_parent, right_parent),
    ]

    # check two added components right side one via c ref
    left_parent.componentReferences = []
    right_parent.componentReferences = [c_ref(c4.name, c4.version)]
    diff = cnudie.util.diff_component_dependency_versions(
        left_component=left_parent,
        right_component=right_parent,
        resolve_function=resolve_ref,
    )
    assert list(diff) == [
        {'parent': right_parent, 'left': None, 'right': c4},
        {'parent': c4, 'left': None, 'right': c5},
        {'parent': None, 'left': left_parent, 'right': right_parent},
    ]
