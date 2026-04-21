## 2024-05-18 - Improve Empty List View
**Learning:** Add visual loading state and description text instead of a blank UI on list pages that take time to scan/load. Ensure to add string resources into values xml before referencing them to prevent compilation failures.
**Action:** When adding UX improvements referencing strings in Jetpack Compose, manually verify that those strings actually exist or create them. Do not rely entirely on the LLM generating the code to be perfect with imports or string files.
