import argparse
import json
import ssl
import time
import os
import threading
from hashlib import sha256
from python_nostr.nostr import bech32
from python_nostr.nostr.event import Event, EventKind
from python_nostr.nostr.filter import Filters, Filter
from python_nostr.nostr.message_pool import MessagePool
from python_nostr.nostr.message_type import ClientMessageType
from python_nostr.nostr.relay_manager import RelayManager
from python_nostr.nostr.key import PrivateKey, PublicKey

PRIVATE_KEY: str = None

# Helper functions
def bech32_decode(key: str) -> bytes:
    data = bech32.bech32_decode(key)[1]
    return bytes(bech32.convertbits(data, 5, 8, False))

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
    private_key = PrivateKey(bech32_decode(PRIVATE_KEY))
    return private_key.decrypt_message(encrypted_content, public_key)

def decrypt_decoy_proof(decoy_public_key: str, encrypted_content: str):
    private_key = PrivateKey(bech32_decode(PRIVATE_KEY))
    return private_key.decrypt_message(encrypted_content, decoy_public_key)

def verify_decoy_proof_content(message: str, public_key: str, signature: str):
    pk = PublicKey(bytes.fromhex(public_key))
    msg_hash = sha256(message.encode()).hexdigest()
    if not pk.verify_signed_message_hash(msg_hash, signature):
        return False

    return True

def create_decoy_proof_event(recipient_public_key: str) -> Event:
    private_key = PrivateKey(bech32_decode(PRIVATE_KEY))
    real_shared_secret = private_key.compute_shared_secret(recipient_public_key)
    scalar = sha256(real_shared_secret).digest()
    sender_decoy_private_key = PrivateKey(private_key.tweak_add(scalar))

    msg = f"dk:{sender_decoy_private_key.public_key.hex()}"
    content_json = {
        "msg": msg,
        "pk": private_key.public_key.hex(),
        "sig": private_key.sign_message_hash(sha256(msg.encode()).digest())
    }

    throwaway_key = PrivateKey()
    encrypted_content = throwaway_key.encrypt_message(json.dumps(content_json), recipient_public_key)
    event = Event(throwaway_key.public_key.hex(), encrypted_content, kind=12, tags=[['p', recipient_public_key]])
    event.sign(throwaway_key.hex())

    return event

def get_decoy_inbox_hash(shared_secret: bytes, public_key: str) -> str:
    sum = PrivateKey(shared_secret).tweak_add(bytes.fromhex(public_key))
    return sha256(sum).hexdigest()

def create_dm_event(recipient_public_key: str, content: str) -> Event:
    private_key = PrivateKey(bech32_decode(PRIVATE_KEY))
    real_shared_secret = private_key.compute_shared_secret(recipient_public_key)
    scalar = sha256(real_shared_secret).digest()
    sender_decoy_private_key = PrivateKey(private_key.tweak_add(scalar))

    encrypted_content = private_key.encrypt_message(content, recipient_public_key)
    recipient_decoy_inbox_hash = get_decoy_inbox_hash(real_shared_secret, recipient_public_key)

    event = Event(sender_decoy_private_key.public_key.hex(), encrypted_content, kind=EventKind.ENCRYPTED_DIRECT_MESSAGE, tags=[['p', recipient_decoy_inbox_hash]])
    event.sign(sender_decoy_private_key.hex())

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
                        print("Unknown sender public key.")
                        return
                    decrypted_content = decrypt_dm(sender_real_public_key, event_message.event.content)
                    print(f"Received a DM from {PublicKey(bytes.fromhex(sender_real_public_key)).bech32()} via your Decoy Inbox Hash {event_message.event.tags[0][1]}")
                    print(decrypted_content)
                elif event_message.event.kind == 12:
                    decrypted_content = decrypt_decoy_proof(event_message.event.public_key, event_message.event.content)
                    decrypted_content_json = json.loads(decrypted_content)
                    message = decrypted_content_json["msg"]
                    sender_real_public_key = decrypted_content_json["pk"]
                    signature = decrypted_content_json["sig"]
                    if verify_decoy_proof_content(message, sender_real_public_key, signature):
                        sender_decoy_public_key = message[3:]
                        save_decoy_public_key(sender_real_public_key, sender_decoy_public_key)
                        print(f"{PublicKey(bytes.fromhex(sender_real_public_key)).bech32()} proved their decoy key is {PublicKey(bytes.fromhex(sender_decoy_public_key)).bech32()}")
        
        if message_pool.has_eose_notices():
            break

# CLI actions
def generate_key(args):
    private_key = PrivateKey()
    print(f"private key: {private_key.bech32()}")
    print(f"public key: {private_key.public_key.bech32()}")

def set_key(args):
    with open("current-private-key.txt", 'w') as outfile:
        outfile.write(args.private_key)

def prove_decoy(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    event = create_decoy_proof_event(bech32_decode(args.public_key).hex())
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
    time.sleep(0.75)
    relay_manager.close_connections()
    print(f"Sent a Decoy Key Proof event to {args.public_key}")
    print(f"Event details at https://nostr.com/e/{event.id}")

def send_dm(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    event = create_dm_event(bech32_decode(args.public_key).hex(), args.content)
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
    time.sleep(0.75)
    relay_manager.close_connections()
    print(f"Sent a DM to {args.public_key} via their Decoy Inbox Hash {event.tags[0][1]}")
    print(f"Event details at https://nostr.com/e/{event.id}")

def get_decoy_proof(args):
    if PRIVATE_KEY is None:
        print("No private key set. Generate and set a new private key")
        return

    private_key = PrivateKey(bech32_decode(PRIVATE_KEY))
    filters = Filters([Filter(kinds=[12], tags={"#p": [private_key.public_key.hex()]})])
    
    subscription_id = os.urandom(4).hex()
    message = [ClientMessageType.REQUEST, subscription_id]
    message.extend(filters.to_json_array())

    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")
    relay_manager.add_subscription(subscription_id, filters)
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    time.sleep(1.25)
    relay_manager.publish_message(json.dumps(message))
    time.sleep(0.5)

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

    private_key = PrivateKey(bech32_decode(PRIVATE_KEY))
    sender_public_key = PublicKey(bech32_decode(args.public_key))
    shared_secret = private_key.compute_shared_secret(sender_public_key.hex())
    decoy_inbox_hash = get_decoy_inbox_hash(shared_secret, private_key.public_key.hex())

    with open(f"{PRIVATE_KEY}-address-book.json", 'r') as infile:
        saved_decoy_public_keys = json.load(infile)
    
    sender_decoy_public_key = saved_decoy_public_keys[sender_public_key.hex()]
    filters = Filters([Filter(kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE], authors=[sender_decoy_public_key], tags={"#p": [decoy_inbox_hash]})])
    
    subscription_id = os.urandom(4).hex()
    message = [ClientMessageType.REQUEST, subscription_id]
    message.extend(filters.to_json_array())

    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")
    relay_manager.add_subscription(subscription_id, filters)
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    time.sleep(1.25)
    relay_manager.publish_message(json.dumps(message))
    time.sleep(0.5)

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
