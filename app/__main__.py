"""Allow ``python3 -m app`` as a shortcut for ``python3 -m app.main``."""

from .main import main

raise SystemExit(main())
