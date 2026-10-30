# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used Claude to explain the task, to draft passwords.py, policy.py and validation.py, and to help me fix errors. I ran the tests myself and fixed the pasted code when it failed.

## What AI got wrong

One thing that went wrong when I pasted the policy.py code, the dataclasses (User, Document, Decision) were deleted from the file. I noticed when pytest failed with "NameError: name 'Decision' is not defined". I restored the dataclasses by rewriting the whole file, then ran pytest again and the error was gone.

## In my own words


1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?

A 403 tells the client that the contract exists but they are not allowed to access it. This causes Information Disclosure because another client can learn that the contract exists. A 404 hides this information by making it look like the contract does not exist

2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?

A stored hash shorter than 32 bytes may be truncated. If the code compared only as many bytes as the stored hash has a truncated hash could pass by matching just a small part, so verify_password must require exactly 32 bytes.
