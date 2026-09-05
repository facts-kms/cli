# Name missing clone dependency identities.

- Clone failures caused by missing dependencies now include the missing object or identity context when it can be inferred from the bundle.
- Authorization grants that reference an absent actor now name the receiving actor and suggest including the identity bundle.

