#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
"""Shared methods."""


from ansible.module_utils.six import (
    binary_type,
    integer_types,
    text_type,
)


from ansible.module_utils._text import to_native

from ansible.module_utils.common._collections_compat import (
    KeysView,
    Mapping,
    Sequence)

# Note: When getting Sequence from collections, it matches with strings. If
# this matters, make sure to check for strings before checking for sequencetype
SEQUENCETYPE = frozenset, KeysView, Sequence

NoneType = type(None)   # Python2 & 3 way to get NoneType
NUMBERTYPES = tuple(list(integer_types) + [float])


def return_values(obj):
    """ Return native stringified values from datastructures.

    For use with removing sensitive values pre-jsonification."""
    if isinstance(obj, (text_type, binary_type)):
        if obj:
            yield to_native(obj, errors='surrogate_or_strict')
        return
    elif isinstance(obj, SEQUENCETYPE):
        for element in obj:
            for subelement in return_values(element):
                yield subelement
    elif isinstance(obj, Mapping):
        for element in obj.items():
            for subelement in return_values(element[1]):
                yield subelement
    elif isinstance(obj, (bool, NoneType)):
        # This must come before int because bools are also ints
        return
    elif isinstance(obj, NUMBERTYPES):
        yield to_native(obj, nonstring='simplerepr')
    else:
        raise TypeError('Unknown parameter type: %s, %s' % (type(obj), obj))

