
1) Run: python patch_localizer.py advisories.csv outputs
2) For each advisory, inspect prompts/ and gumtree/ and the git diffs in outputs.
3) To localize vulnerability automatically: send the localization prompt file + the GumTree JSON(s) to an LLM capable of handling large JSON (or attach a representative snippet).
   - Use the LOCALIZATION_PROMPT (already saved) and include at most 3-5 GumTree outputs per request.
4) To check whether patch fixes the vulnerable version: send FIX_CHECK_PROMPT + the unified git diff file to the LLM.

Prompt-engineering tips:
 - Give the model the exact CWE category (CWE-79) and short examples of what constitutes a fix (escaping user input, introducing sanitation, removing dangerous sinks).
 - Provide a short test plan for the model to produce (inputs to try, endpoints to fuzz) so it's easier to validate its answer.
 - Ask the model for a confidence (0-100) and concrete verification steps.

