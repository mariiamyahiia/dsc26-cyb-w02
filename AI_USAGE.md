# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used Claude to help organize YAML threat entries, to fix the validation rules for the command line interface output and to improve the threat descriptions, for the Rawaj Pay analyst console and the scoring service

## What AI got wrong

## What AI got wrong

The AI first gave string values of numbers for the chance and effect scores of the new dangers. this made the parser not accept the setup. I noticed this when running `python -m tmcheck` because the script had a problem when loading the data. I fixed it by taking the quotes from the numbers so they were in the right number format

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
A data store is a place where data sits. it doesn’t reach out to parts of the system or claim to be something it’s not, so it can’t be "spoofed" like a user or service might. the real risks come from what touches the data store, like the programs or people accessing it, the passwords or keys they use and what data is being sent into it. if someone tries to pretend to be someone or mess with the data coming in, that’s where the danger lies. the data store itself doesn’t do anything on its own. it just holds what’s given to it

2. Which of your eleven new threats would you fix first, and why that one?
T31 (hacker bypasses the system to delete fraud warnings from suspicious user profiles)
why: if someone gets access to the database and changes the flagged cases on their own, they can remove the fraud flags from accounts. this breaks the goal of the whole scoring and fraud-detection system, it makes all the checks that happen before this useless