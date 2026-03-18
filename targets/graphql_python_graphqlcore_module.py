"""Persistent module -- graphql-core Python GraphQL analyzer."""

from graphql_python_graphqlcore import analyze_query


def process(input_str):
    try:
        output = analyze_query(input_str)
        return {"output": output, "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
