"""Near-miss analysis: coverage frontier extraction for differential fuzzing.

Replays corpus through instrumented targets, identifies uncovered branches
adjacent to covered code (frontier branches), and scores them for security
relevance so users can analyze with LLM and design targeted mutations.
"""
