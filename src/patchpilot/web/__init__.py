"""Read-only local web dashboard for PatchPilot analysis history.

The application is created by :func:`patchpilot.web.app.create_app`; this
package intentionally imports nothing eagerly so ``import patchpilot.web`` stays
cheap (the CLI imports ``patchpilot.web.app`` lazily when ``patchpilot web``
actually runs).
"""
