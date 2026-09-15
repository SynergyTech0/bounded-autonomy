# -*- coding: utf-8 -*-
"""elab.py -- underscore-free alias for escape_lab.py (avoids markdown/shell underscore-escaping
when the confined agent copies the command). Same confined surface, nothing else."""
import sys
import escape_lab
if __name__ == "__main__":
    raise SystemExit(escape_lab.main(sys.argv[1:]))
