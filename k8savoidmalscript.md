```yml
---
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8savoidmalscript
spec:
  crd:
    spec:
      names:
        kind: K8sAvoidMalScript
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          properties:
            image:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8savoidmalscript
        violation[{"msg": msg, "details": {"Unallowed code detected": code}}] {
          code := "curl"
          input.review.object.kind == "Pod"
          input.review.object.spec.containers[_].command[_] == input.parameters.code
          msg := sprintf("%v is not allowed:", [code])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAvoidMalScript
metadata:
  name: prevent-malicious-code
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    code: "curl"

```
