# Producer Registry v2

`config/producers-v2.json` separates repository identity from component policy.

A **repository** is the GitHub source/trust boundary. A **component** is an
independently released policy unit inside that repository. A component may
produce one or more RPM package names.

This matters for monorepos such as `Ro-ASD-release`, where
`ro-asd-release`, `ro-asd-keyring`, `ro-asd-repos`, branding and defaults
can share one Git repository while keeping independent risk classes,
architectures, promotion groups and required tests.

## Shape

```json
{
  "repository": "Project-Ro-ASD/Ro-ASD-release",
  "owner": "Project-Ro-ASD/Ro-ASD-release maintainers",
  "components": [
    {
      "component": "ro-asd-release",
      "package_names": ["ro-asd-release"],
      "architectures": ["noarch"],
      "risk_class": "critical-system",
      "promotion_group": "ro-asd-release",
      "required_tests": ["dependency-solve"],
      "srpm_required": true,
      "sbom_required": false,
      "allow_fedora_override": false,
      "trusted_signer_workflow": "Project-Ro-ASD/Ro-ASD-release/.github/workflows/release.yml"
    }
  ]
}
```

The manifest `component` field selects exactly one component policy. Every RPM
in that release must then be listed in that component's `package_names`.

## Migration

`producers-v1.yaml` remains temporarily supported by the Python resolver so
existing tests and older tooling continue to work. New production acceptance
uses v2. Promotion consumers are migrated separately so each change remains
reviewable and reversible.
