import ast
import inspect
import textwrap

from appguardrail_core.org_intelligence import build_org_inventory


def test_build_org_inventory_has_one_repository_traversal_after_materialization():
    """Keep inventory aggregation in the single loop this optimization promises."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(build_org_inventory)))

    repo_list_iterators = []
    for node in ast.walk(tree):
        if isinstance(node, ast.For):
            repo_list_iterators.append(node.iter)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            repo_list_iterators.extend(generator.iter for generator in node.generators)

    traversals = [
        iterator
        for iterator in repo_list_iterators
        if isinstance(iterator, ast.Name) and iterator.id == "repo_list"
    ]

    assert len(traversals) == 1
