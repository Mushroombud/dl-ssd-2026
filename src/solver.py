"""Compatibility facade for the offline Opal rule-based solver.

The implementation is split by function under :mod:`src.solver_components`.
This module intentionally re-exports component symbols so older imports from
``src.solver`` continue to work.
"""

from .solver_components import constants as _constants
from .solver_components import models as _models
from .solver_components import parsing as _parsing
from .solver_components import semantics as _semantics
from .solver_components import expectations as _expectations
from .solver_components import transitions as _transitions
from .solver_components import engine as _engine

for _module in (
    _constants,
    _models,
    _parsing,
    _semantics,
    _expectations,
    _transitions,
    _engine,
):
    globals().update({
        _name: _value
        for _name, _value in vars(_module).items()
        if not (_name.startswith("__") and _name.endswith("__"))
    })

__all__ = [
    _name
    for _name in globals()
    if not (_name.startswith("__") and _name.endswith("__"))
]
