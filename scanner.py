
def probe_unauthenticated(url):
    """Run unauthenticated discovery probes"""
    from tests.test_unauthenticated_probes import UnauthenticatedProbeTest
    tester = UnauthenticatedProbeTest(url)
    return tester.run_all()

def probe_unauthenticated(url):
    """Run unauthenticated discovery probes"""
    from tests.test_unauthenticated_probes import UnauthenticatedProbeTest
    tester = UnauthenticatedProbeTest(url)
    return tester.run_all()
