import argparse
import json
import ssl
import time
import os
import threading
from hashlib import sha256
from python_nostr.nostr.event import Event, EventKind
from python_nostr.nostr.filter import Filters, Filter
from python_nostr.nostr.message_pool import MessagePool
from python_nostr.nostr.message_type import ClientMessageType
from python_nostr.nostr.relay_manager import RelayManager
from python_nostr.nostr.key import (
    decrypt_message, compute_shared_secret, encrypt_message, 
    get_key_pair, get_public_key, sign_message, tweak_add_private_key, 
    verify_message)

PRIVATE_KEY = None

# Helper functions
def get_real_public_key_from_decoy(decoy_public_key: str) -> str:
    with open(f"{PRIVATE_KEY}-address-book.json", 'r') as infile:
        saved_decoy_public_keys = dict(json.load(infile))

    for public_key, decoy_key in saved_decoy_public_keys.items():
        if decoy_key == decoy_public_key:
            return public_key

    return None

def save_decoy_public_key(real_public_key: str, decoy_public_key: str):
    try:
        with open(f"{PRIVATE_KEY}-address-book.json", 'r') as infile:
            saved_decoy_public_keys = dict(json.load(infile))
    except FileNotFoundError:
        with open(f"{PRIVATE_KEY}-address-book.json", 'x'):
            saved_decoy_public_keys = {}

    saved_decoy_public_keys[real_public_key] = decoy_public_key
    with open(f"{PRIVATE_KEY}-address-book.json", 'w') as outfile:
        json.dump(saved_decoy_public_keys, outfile, indent=4)

def decrypt_dm(public_key: str, encrypted_content: str) -> str:
    shared_secret = compute_shared_secret(PRIVATE_KEY, public_key)
    return decrypt_message(encrypted_content, shared_secret)

def decrypt_decoy_proof(decoy_public_key: str, encrypted_content: str):
    decoy_shared_secret = compute_shared_secret(PRIVATE_KEY, decoy_public_key)
    return decrypt_message(encrypted_content, decoy_shared_secret)

def verify_decoy_proof_content(message: str, decoy_public_key: str, real_public_key: str, signature: str):
    msg_hash = sha256(message.encode()).hexdigest()
    if not verify_message(msg_hash, signature, real_public_key):
        return False
    
    decoy_pk = message[3:]
    if not decoy_pk == decoy_public_key:
        return False

    return True

def create_decoy_proof_event(recipient_public_key: str) -> Event:
    real_shared_secret = compute_shared_secret(PRIVATE_KEY, recipient_public_key)
    scalar = sha256(real_shared_secret.encode()).digest()
    sender_decoy_private_key = tweak_add_private_key(PRIVATE_KEY, scalar)
    sender_decoy_public_key = get_public_key(sender_decoy_private_key)

    msg = f"dk:{sender_decoy_public_key}"
    content_json = {
        "msg": msg,
        "pk": get_public_key(PRIVATE_KEY),
        "sig": sign_message(sha256(msg.encode()).hexdigest(), PRIVATE_KEY)
    }

    decoy_shared_secret = compute_shared_secret(sender_decoy_private_key, recipient_public_key)
    encrypted_content = encrypt_message(json.dumps(content_json), decoy_shared_secret)

    event = Event(sender_decoy_public_key, encrypted_content, kind=7476, tags=[['p', recipient_public_key]])
    event.sign(sender_decoy_private_key)

    return event

def get_decoy_inbox_hash(shared_secret: str, public_key: str) -> str:
    return sha256(f"{sha256(shared_secret.encode()).hexdigest()}{public_key}".encode()).hexdigest()

def create_dm_event(recipient_public_key: str, content: str) -> Event:
    shared_secret = compute_shared_secret(PRIVATE_KEY, recipient_public_key)
    scalar = sha256(shared_secret.encode()).digest()
    sender_decoy_private_key = tweak_add_private_key(PRIVATE_KEY, scalar)
    sender_decoy_public_key = get_public_key(sender_decoy_private_key)

    encrypted_content = encrypt_message(content, shared_secret)
    recipient_decoy_inbox_hash = get_decoy_inbox_hash(shared_secret, recipient_public_key)

    event = Event(sender_decoy_public_key, encrypted_content, kind=EventKind.ENCRYPTED_DIRECT_MESSAGE, tags=[['p', recipient_decoy_inbox_hash]])
    event.sign(sender_decoy_private_key)

    return event

# Thread function for handling messages from relay
def handle_messages(message_pool: MessagePool):
    while True:
        while message_pool.has_notices() or message_pool.has_events():
            if message_pool.has_notices():
                notice_message = message_pool.get_notice()
                print(f"[{notice_message.url}][NOTICE] {notice_message.content}")
            if message_pool.has_events():
                event_message = message_pool.get_event()
                if event_message.event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
                    sender_real_public_key = get_real_public_key_from_decoy(event_message.event.public_key)
                    if sender_real_public_key is None:
                        print("Unknown author public key.")
                        return
                    decrypted_content = decrypt_dm(sender_real_public_key, event_message.event.content)
                    print(f"Received a DM from {sender_real_public_key} at your Decoy Inbox Hash {event_message.event.tags[0][1]}")
                    print(decrypted_content)
                elif event_message.event.kind == 7476:
                    decrypted_content = decrypt_decoy_proof(event_message.event.public_key, event_message.event.content)
                    decrypted_content_json = json.loads(decrypted_content)
                    message = decrypted_content_json["msg"]
                    sender_real_public_key = decrypted_content_json["pk"]
                    signature = decrypted_content_json["sig"]
                    if verify_decoy_proof_content(message, event_message.event.public_key, sender_real_public_key, signature):
                        save_decoy_public_key(sender_real_public_key, event_message.event.public_key)
                        print(f"{sender_real_public_key} proved their decoy key is {event_message.event.public_key}")
        
        if message_pool.has_eose_notices():
            break

# CLI actions
def generate_key(args):
    private_key, public_key = get_key_pair()
    print(f"private key: {private_key}")
    print(f"public key: {public_key}")

def set_key(args):
    with open("current-private-key.txt", 'w') as infile:
        infile.write(args.private_key)

def prove_decoy(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    event = create_decoy_proof_event(args.public_key)
    message = [ClientMessageType.EVENT, event.to_json_object()]

    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    time.sleep(1.25)
    relay_manager.publish_message(json.dumps(message))

    messages_thread = threading.Thread(
        target=handle_messages,
        args=(relay_manager.message_pool,),
        name="handle-messages",
        daemon=True
    )
    messages_thread.start()
    time.sleep(0.5)
    relay_manager.close_connections()
    print(f"Sent a Decoy Key Proof event to {args.public_key}")
    print(f"Event details at https://nostr.com/e/{event.id}")

def send_dm(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    event = create_dm_event(args.public_key, args.content)
    message = [ClientMessageType.EVENT, event.to_json_object()]

    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    time.sleep(1.25)
    relay_manager.publish_message(json.dumps(message))

    messages_thread = threading.Thread(
        target=handle_messages,
        args=(relay_manager.message_pool,),
        name="handle-messages",
        daemon=True
    )
    messages_thread.start()
    time.sleep(0.5)
    relay_manager.close_connections()
    print(f"Send a DM to {args.public_key} at their Decoy Inbox Hash {event.tags[0][1]}")
    print(f"Event details at https://nostr.com/e/{event.id}")

def get_decoy_proof(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    recipient_public_key = get_public_key(PRIVATE_KEY)
    filters = Filters([Filter(kinds=[7476], tags={"#p": [recipient_public_key]})])
    
    subscription_id = os.urandom(4).hex()
    message = [ClientMessageType.REQUEST, subscription_id]
    message.extend(filters.to_json_array())

    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")
    relay_manager.add_subscription(subscription_id, filters)
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    time.sleep(1.25)
    relay_manager.publish_message(json.dumps(message))

    messages_thread = threading.Thread(
        target=handle_messages,
        args=(relay_manager.message_pool,),
        name="handle-messages"
    )
    messages_thread.start()
    messages_thread.join()
    relay_manager.close_connections()

def get_dm(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    recipient_public_key = get_public_key(PRIVATE_KEY)
    shared_secret = compute_shared_secret(PRIVATE_KEY, args.public_key)
    recipient_decoy_inbox_hash = get_decoy_inbox_hash(shared_secret, recipient_public_key)

    with open(f"{PRIVATE_KEY}-address-book.json", 'r') as infile:
        saved_decoy_public_keys = json.load(infile)
    
    sender_decoy_public_key = saved_decoy_public_keys[args.public_key]
    filters = Filters([Filter(kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE], authors=[sender_decoy_public_key], tags={"#p": [recipient_decoy_inbox_hash]})])
    
    subscription_id = os.urandom(4).hex()
    message = [ClientMessageType.REQUEST, subscription_id]
    message.extend(filters.to_json_array())

    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")
    relay_manager.add_subscription(subscription_id, filters)
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    time.sleep(1.25)
    relay_manager.publish_message(json.dumps(message))

    messages_thread = threading.Thread(
        target=handle_messages,
        args=(relay_manager.message_pool,),
        name="handle-messages"
    )
    messages_thread.start()
    messages_thread.join()
    relay_manager.close_connections()

def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    key_parser = subparsers.add_parser("key")
    key_subparsers = key_parser.add_subparsers()

    key_gen = key_subparsers.add_parser("gen")
    key_gen.set_defaults(func=generate_key)

    key_set = key_subparsers.add_parser("set")
    key_set.add_argument("private_key")
    key_set.set_defaults(func=set_key)

    dm_parser = subparsers.add_parser("dm")
    dm_subparsers = dm_parser.add_subparsers()

    dm_prove = dm_subparsers.add_parser("provedecoy")
    dm_prove.add_argument("public_key")
    dm_prove.set_defaults(func=prove_decoy)

    dm_send = dm_subparsers.add_parser("send")
    dm_send.add_argument("public_key")
    dm_send.add_argument("content")
    dm_send.set_defaults(func=send_dm)

    dm_get_proof = dm_subparsers.add_parser("getdecoyproof")
    dm_get_proof.set_defaults(func=get_decoy_proof)

    dm_get = dm_subparsers.add_parser("get")
    dm_get.add_argument("public_key")
    dm_get.set_defaults(func=get_dm)

    return parser

if __name__ == "__main__":
    try:
        with open("current-private-key.txt", 'r') as infile:
            PRIVATE_KEY = infile.read().strip()
    except FileNotFoundError:
        PRIVATE_KEY = None

    parser = setup_parser()
    args = parser.parse_args()
    args.func(args)
    parser.exit()
