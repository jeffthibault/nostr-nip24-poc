# nostr-nip24-poc

## Walkthrough
Note: I wrote this in Python 3.9.5

**Step 1**: Open a terminal and clone this repository
```bash
git clone https://github.com/jeffthibault/nostr-nip24-poc.git
```

**Step 2**: Navigate into the repository
```bash
cd nostr-nip24-poc
```

**Step 3**: Create a virtual environment
```bash
python -m venv venv
```

**Step 4**: Install dependencies
```bash
pip install wheel
pip install -r python_nostr/requirements.txt
```

**Step 5**: Generate a private and public key pair. These keys will be known as `privkey1` and `pubkey1`.
```bash
python nip24-poc.py key gen
```
Note: Copy these keys somewhere because they are needed in the next steps.
 
**Step 6**: Generate another private and public key pair. These keys will be known as `privkey2` and `pubkey2`.
```bash
python nip24-poc.py key gen
```
Note: Again, copy these keys somewhere because they are needed in the next steps.
 
**Step 7**: Set `privkey1` as the current key. You are now interacting from `privkey1`'s perspective.
```bash
python nip24-poc.py key set <privkey1>
```
You will see a file created called `current-private-key.txt` containing `privkey1`
 
**Step 8**: Send a Decoy Key Proof event to `pubkey2`
```bash
python nip24-poc.py dm provedecoy <pubkey2>
```
You will see a confirmation that the proof was sent to `pubkey2` and a link to view the event details on nostr.com.
 
**Step 9**: Send a DM event to `pubkey2`
```bash
python nip24-poc.py dm send <pubkey2> 'Hello, this is nip24 poc test'
```
You will see a confirmation that the DM was sent to `pubkey2`'s decoy inbox hash and a link to view the event details.
 
**Step 10**: Set `privkey2` as the current key. You are now interacting from `privkey2`'s perspective.
```bash
python nip24-poc.py key set <privkey2>
```
The file `current-private-key.txt` now contains `privkey2`
 
**Step 11**: Receive the Decoy Key Proof event from `pubkey1`
```bash
python nip24-poc.py dm getdecoyproof
```
You will see a confirmation that `pubkey1` proved their decoy key and a new file created called `<privkey2>-address-book.json` which contains a map between `pubkey1`'s real public key and decoy public key.

**Step 12**: Receive the DM event from `pubkey1`
```bash
python nip24-poc.py dm get <pubkey1>
```
You will see a confirmation that you received a DM from `pubkey1` at your Decoy Inbox Hash and the decrypted content.
 
**Step 13**: Send a Decoy Key Proof event to `pubkey1`
```bash
python nip24-poc.py dm provedecoy <pubkey1>
```
You will see a confirmation that the proof was sent to `pubkey1` and a link to view the event details.
  
**Step 14**: Send a DM event to `pubkey1`
```bash
python nip24-poc.py dm send <pubkey1> 'Hi, I received your nip24 message'
```
You will see a confirmation that the DM was sent to `pubkey1`'s Decoy Inbox Hash and a link to view the event details.
  
**Step 15**: Set `privkey1` as the current key. You are now interacting from `privkey1`'s perspective.
```bash
python nip24-poc.py key set <privkey1>
```
The file `current-private-key.txt` now contains `privkey1`
 
**Step 16**: Receive the Decoy Key Proof event from `pubkey2`
```bash
python nip24-poc.py dm getdecoyproof
```
You will see a confirmation that `pubkey2` proved their decoy key and a new file created called `<privkey1>-address-book.json` which contains a map between `pubkey2`'s real public key and decoy public key.
 
**Step 17**: Receive the DM event from `pubkey2`
```bash
python nip24-poc.py dm get <pubkey2>
```
You will see a confirmation that you received a DM from `pubkey2` at your Decoy Inbox Hash and the decrypted content.
  
That's it. You sent private DMs on Nostr!
 
