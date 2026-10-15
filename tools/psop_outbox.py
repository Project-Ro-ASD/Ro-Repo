"""Reuse V3 durable lease/fence/locked guards with PSOP atomic enqueue."""
from v3_publication_outbox import Outbox as V3Outbox


class Outbox(V3Outbox):
    def enqueue(self, prepared, approval, *, inject=None):
        return self.ledger.enqueue(prepared, approval, inject=inject)


class Backend:
    def __init__(self, ledger):
        self.ledger = ledger

    def _fresh(self, expiry):
        self.ledger._fresh(expiry)
