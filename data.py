import json
from pathlib import Path
from typing import Optional

from sqlcipher3 import dbapi2
from typer import Exit, colors, secho

from helpers import models
from helpers.logging import log

def fetch_data(key:str, db_file: str, chats: str, include_empty: bool,):

    contacts: models.Contacts = {}
    convos: models.Convos = {}
    chats_list = chats.split(",") if len(chats) > 0 else []

    db = dbapi2.connect(str(db_file))
    c = db.cursor()
    # param binding doesn't work for pragmas, so use a direct string concat
    c.execute(f"PRAGMA KEY = \"x'{key}'\"")
    c.execute("PRAGMA cipher_page_size = 4096")
    c.execute("PRAGMA kdf_iter = 64000")
    c.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    c.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")

    query = "SELECT type, id, serviceId, e164, name, profileName, members FROM conversations"
    c.execute(query)
    for result in c:
        log(f"\tLoading SQL results for: {result[4]}, aka {result[5]}")
        members = []
        if result[6]:
            members = result[6].split(" ")
        is_group = result[0] == "group"
        cid = result[1]
        contacts[cid] = models.Contact(
            id=cid,
            serviceId=result[2],
            name=result[4],
            number=result[3],
            profile_name=result[5],
            members=members,
            is_group=is_group,
        )
        if contacts[cid].name is None:
            contacts[cid].name = contacts[cid].profile_name

        if not chats or (result[4] in chats_list or result[5] in chats_list):
            convos[cid] = []

    query = "SELECT * FROM messages ORDER BY sent_at"
    c.execute(query)
    for result in c:
        json_result = json.loads(result[2])
        if result[14] in ["keychange", "profile-change"]:
            continue
        con = models.RawMessage(
            conversation_id=result[7],
            id=result[1],
            type=result[14],
            body=result[15],
            contact=json_result.get("contact"),
            source=json_result.get("sourceServiceId"),
            timestamp=result[39],
            sent_at=result[5],
            server_timestamp=result[42],
            has_attachments=result[9],
            attachments=json_result.get("attachments", []),
            read_status=result[3],
            seen_status=result[28],
            call_history=json_result.get("call_history"),
            reactions=json_result.get("reactions", []),
            sticker=json_result.get("sticker"),
            quote=json_result.get("quote"),
        )
        convos[result[7]].append(con)
    if not include_empty:
        convos = {key: val for key, val in convos.items() if len(val) > 0}
    
    return convos,contacts