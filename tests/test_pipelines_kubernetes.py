from sigma.backends.kusto.elasticsearch_lucene import LuceneBackend
from sigma.pipelines.kusto.ms_xdr import ms_xdr
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule


def test_ecs_kubernetes():
    assert (
        LuceneBackend(ms_xdr()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  resource: pods
                condition: selection
        """
            )
        )
        == [
            "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods)"
        ]
    )


def test_ecs_kubernetes_apigroup():
    assert (
        LuceneBackend(ms_xdr()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  apiGroup: authorization.k8s.io
                  resource: selfsubjectrulesreviews
                condition: selection
        """
            )
        )
        == [
            "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.apiGroup:authorization.k8s.io AND kubernetes.audit.objectRef.resource:selfsubjectrulesreviews)"
        ]
    )


def test_ecs_kubernetes_capabilities():
    assert (
        LuceneBackend(ms_xdr()).convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  resource: pods
                  capabilities: "*"
                condition: selection
        """
            )
        )
        == [
            "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods AND kubernetes.audit.requestObject.spec.containers.securityContext.capabilities.add:*)"
        ]
    )

    def test_ecs_kubernetes_subresource():
        assert (
            LuceneBackend(ms_xdr()).convert(
                SigmaCollection.from_yaml(
                    """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                  verb: create
                  resource: pods
                  subresource: exec
                condition: selection
        """
                )
            )
            == [
                "kubernetes.audit.kind:Event AND (kubernetes.audit.verb:create AND kubernetes.audit.objectRef.resource:pods AND kubernetes.audit.objectRef.subresource:exec)"
            ]
        )


def test_ecs_kubernetes_fields():
    rule = ms_xdr().apply(
        SigmaRule.from_yaml(
            """
            title: Test
            status: test
            logsource:
                product: kubernetes
                service: audit
            detection:
                selection:
                    verb: create
                    resource: pods
                    hostPath: "*"
                condition: selection
            fields:
                - verb
                - hostPath
        """
        )
    )
    assert rule.fields == [
        "kubernetes.audit.verb",
        "kubernetes.audit.requestObject.spec.volumes.hostPath",
    ]
