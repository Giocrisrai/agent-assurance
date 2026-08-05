"""Adaptador del objetivo.

Cada agente expone su chat con una forma distinta: unos esperan
`{"mensaje": "..."}`, otros `{"message": "...", "session_id": "..."}`.
El adaptador aisla esa variabilidad para que las