#!/usr/bin/env python3
"""
Plain-English glosses for every risk across every IEM-AIS test case --
authored by this project, NOT fetched from OWASP. Per
Project DOCS/IEM-AIS-Practical-Build-Roadmap.md §4 item 1: "a plain-
English gloss written by us... clearly labeled as our paraphrase, never
presented as an OWASP quote." Same category of judgment-call content as
each skill's own RISK_TO_CONTROLS mapping -- defensible analysis, not
something fact-checkable against the live PDF.

Keyed by (test_case_key, risk_id) matching ui/server.py's TEST_CASES
keys and each skill's own risk_id numbering. report_builder.py looks
these up; a missing entry renders an honest "(no plain-English gloss
written yet for this risk)" rather than silently omitting the row or
inventing one on the fly.
"""

LAYMAN_GLOSSES = {
    "jailbreaking": {
        1: "Can someone just tell the bot 'ignore your rules' and have it work?",
        2: "Can a poisoned webpage or document the bot reads make it do something it shouldn't, without the attacker ever typing to it directly?",
        3: "Can a message left somewhere the bot's OWNER trusts (a support ticket, a form) trick the bot into using its own elevated access against its owner?",
        4: "Can an attacker hide instructions inside an image or audio clip that a human reviewer would never notice, but the bot still follows?",
        5: "Can an attacker hide invisible characters in ordinary-looking text to smuggle in secret instructions or sneak data back out?",
        6: "If the bot remembers things across conversations, can one attacker plant a bad instruction that then affects a completely different user later?",
        7: "If the bot can be fine-tuned/retrained, can an attacker use that retraining process itself as a side channel to craft attacks?",
        8: "Can an attacker slip past the bot's filters just by writing the attack in another language, or encoding/splitting it up?",
    },
    "sensitive_info": {
        1: "Can you get the bot to spit out exact chunks of the private data it was trained on?",
        2: "During a normal conversation, can the bot accidentally reveal internal details (its own reasoning, other users' info, secrets) it shouldn't share?",
        3: "If the bot uses a searchable knowledge base behind the scenes, can that search mechanism itself leak private information?",
        4: "If the bot can see images, audio, or documents, can it be tricked into reading out private details buried inside them (like text in a screenshot)?",
        5: "Even without a straight answer, can an attacker figure out private information just by measuring how the bot behaves (timing, response patterns)?",
        6: "Could someone learn private details about how the bot itself was built or trained, just by interacting with it?",
        7: "Do the tools/logging/observability systems around the bot leak private data even if the bot's own replies don't?",
    },
    "output_handling": {
        1: "If the bot's reply gets fed straight into a command line or code-execution step somewhere downstream, could that let an attacker run arbitrary commands?",
        2: "If the bot's reply gets displayed as-is on a webpage, could an attacker make it output malicious code that runs in someone else's browser?",
        3: "If the bot's reply gets used to build a database query, could an attacker manipulate it into a database attack?",
        4: "If the bot's reply gets used to build a file path, could an attacker make it read/write files it shouldn't?",
        5: "If the bot's reply gets dropped into an email template, could an attacker use it to craft a convincing phishing email?",
        6: "If the bot's reply gets shown in a terminal or log viewer, could hidden control characters make it fake output or hijack the display?",
        7: "If the bot's reply can contain an image link that auto-loads, could an attacker use that to secretly leak conversation data to their own server?",
    },
    "unbounded_consumption": {
        1: "Can someone flood the bot with oddly-sized requests to make it slow or unresponsive for everyone else?",
        2: "Can someone rack up a huge bill on the bot owner's behalf just by sending lots of requests?",
        3: "Can someone send requests that sit right at the size limit, over and over, to quietly burn far more compute than a normal question would?",
        4: "Can a short, innocent-looking question trick the bot into an extremely long 'thinking' loop that burns resources?",
        5: "Can someone use specially crafted (not just long) inputs to force the bot to work much harder than it should?",
        6: "Do images/audio/video sent to the bot cost dramatically more to process than a normal text question, in a way that could be abused?",
        7: "Could someone systematically query the bot to essentially copy/steal a working replica of it?",
        8: "If the bot can call other tools, can an attacker make it call them over and over in a runaway loop?",
        9: "Could the underlying serving software itself be attacked to crash or overload the system?",
    },
    "hidden_context": {
        1: "Can you trick the bot into revealing its own secret instructions, passwords, or the tools it has access to?",
        2: "Can you get the bot to explain its own internal decision-making rules in a way that helps you find loopholes?",
        3: "Can you get the bot to reveal exactly what makes it refuse things, so you know precisely how to word around a refusal?",
        4: "Can you get the bot to reveal what special permissions or access levels exist behind the scenes?",
        5: "Can you get the bot to reveal the exact format/template its answers are supposed to follow, so you can forge a fake one?",
    },
    "vector_embedding": {
        1: "In a multi-customer system, can one customer's questions reveal hints about what's in another customer's private documents?",
        2: "If someone steals the bot's internal 'numeric fingerprints' of documents (not the documents themselves), can they reconstruct the original private text from just those numbers?",
        3: "Can an attacker plant content somewhere public so that it gets pulled in and treated as trustworthy background info for someone else's question?",
        4: "Can an attacker plant a decoy document that makes the bot falsely claim 'I don't know that' about something it actually should know?",
        5: "Can an attacker figure out WHETHER a specific sensitive document exists in the system, even without ever seeing its contents?",
        6: "Can an attacker poison the bot's 'similar questions get similar cached answers' shortcut, so it serves the wrong (attacker-chosen) answer?",
        7: "Can an attacker hide a poisoning attack inside an image or audio file instead of text, so text-based safety scans miss it?",
    },
    "excessive_agency": {
        1: "If a tool is only supposed to read data, can it actually be tricked into modifying or deleting it too?",
        2: "Are there old, forgotten tools/features left switched on that shouldn't still be reachable?",
        3: "If a tool can run a specific command, can it be tricked into running OTHER commands it was never meant to allow?",
        4: "Does a 'read-only' feature actually have hidden write/delete power behind the scenes?",
        5: "Does the bot act using one shared powerful account instead of properly limiting itself to just the current user's own access?",
        6: "Will the bot go ahead and take a serious, hard-to-undo action without ever checking with a human first?",
    },
    "misinformation": {
        1: "Could the bot confidently give WRONG advice that leads to a bad real-world decision (financial, legal, medical)?",
        2: "Could the bot wrongly assume some condition was already satisfied, and act on that wrong assumption?",
        3: "Could the bot recommend code or a software package that doesn't even exist, which an attacker could then register and poison?",
        4: "Could the bot's summary quietly leave out an important warning or exception, making things look safer than they are?",
        5: "Can an attacker deliberately feed the bot a false 'fact' and get it to repeat that false fact back as if it were true?",
        6: "In a system with multiple AI agents working together, can one agent's mistake spread and get treated as fact by the others?",
        7: "Could the bot present made-up or altered content as if it were solid, verified proof of something?",
    },
}


def get_layman_gloss(test_case_key, risk_id):
    """Never raises, never invents -- an unwritten gloss says so plainly
    rather than silently omitting the row or fabricating a paraphrase."""
    tc = LAYMAN_GLOSSES.get(test_case_key, {})
    return tc.get(risk_id) or "(no plain-English gloss written yet for this risk)"
