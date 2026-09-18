import re

with open("appguardrail_core/rules.py", "r") as f:
    content = f.read()

# Replace inline merge logic with original method call
inline_merge_search = """    # ⚡ Bolt: Unroll nested generator to avoid frame allocation
    d_ref = {}
    for reference in public_references:
        if reference:
            d_ref[reference] = None
    for reference in CATEGORY_REFERENCE_DEFAULTS.get(category, ()):
        if reference:
            d_ref[reference] = None
    references = tuple(d_ref)"""

inline_merge_replace = """    references = _merge_references(
        public_references,
        CATEGORY_REFERENCE_DEFAULTS.get(category, ()),
    )"""

content = content.replace(inline_merge_search, inline_merge_replace)


# Optimize _merge_references
old_merge = """def _merge_references(*groups: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            reference for group in groups for reference in group if reference
        )
    )"""

new_merge = """def _merge_references(*groups: tuple[str, ...]) -> tuple[str, ...]:
    # ⚡ Bolt: Unroll nested generator to avoid frame allocation
    d_ref = {}
    for group in groups:
        for reference in group:
            if reference:
                d_ref[reference] = None
    return tuple(d_ref)"""

content = content.replace(old_merge, new_merge)

with open("appguardrail_core/rules.py", "w") as f:
    f.write(content)
