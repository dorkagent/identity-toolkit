"""Source-anchor maths shared by import_users.py and verify_immutable_ids.py.

Microsoft Learn (Entra Connect, existing tenant / hard match): the source
anchor "is the Base64 string representation of the mS-Ds-ConsistencyGUID
attribute (or ObjectGUID depending on the configuration) from the
on-premises Active Directory object. This value is set as the
corresponding ImmutableId in Microsoft Entra ID."

The usual recalculation is PowerShell
``[System.Convert]::ToBase64String($guid.ToByteArray())``. .NET
``Guid.ToByteArray()`` writes the first three fields little-endian, which
is exactly Python's ``uuid.UUID(...).bytes_le``.
"""

from __future__ import annotations

import base64
import re
import uuid

GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def immutable_id_from_guid(guid_str: str) -> str:
    """Expected Entra ImmutableID for a GUID-form source anchor.

    Raises ValueError for non-GUID input.
    """
    return base64.b64encode(
        uuid.UUID(guid_str.strip()).bytes_le).decode("ascii")
