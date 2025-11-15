# ajustar_grupos.py
import sqlite3

DB = "questionario.db"

conn = sqlite3.connect(DB)
c = conn.cursor()

# pega os ids dos grupos admin e gestor
admin_gid  = c.execute("SELECT id FROM grupos WHERE nome='admin'").fetchone()[0]
gestor_gid = c.execute("SELECT id FROM grupos WHERE nome='gestor'").fetchone()[0]

# define admin como grupo do usuário 'admin'
c.execute("UPDATE usuarios SET grupo_id=? WHERE username='admin'", (admin_gid,))

# define grupo gestor para os demais que ainda não têm grupo
c.execute("UPDATE usuarios SET grupo_id=COALESCE(grupo_id, ?)", (gestor_gid,))

conn.commit()
conn.close()

print("✅ Grupos ajustados com sucesso.")
