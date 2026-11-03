import XCTest
@testable import Tern

/// probe/kit-e2e diagnosis ONLY: why does the full kit YAML fail ProfileStore.addLocal
/// in the seed while the reduced one imports? Validate the full text, the reduced text
/// (control), and a per-proxy-type subset of the full text through the app's own
/// validator and attach every returned error verbatim.
final class KitImportProbeTests: XCTestCase {

    static let subsets: [(String, String)] = [
        ("socks5", "cHJveGllczoKLSBuYW1lOiBUZXJuLVNPQ0tTNQogIHR5cGU6IHNvY2tzNQogIHNlcnZlcjogNDUu" +
            "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAxCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6" +
            "IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBH" +
            "CiAgdHlwZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tU09DS1M1CnJ1bGVzOgotIE1BVENI" +
            "LEcK"),
        ("http", "cHJveGllczoKLSBuYW1lOiBUZXJuLUhUVFAKICB0eXBlOiBodHRwCiAgc2VydmVyOiA0NS45Mi4x" +
            "NTkuMTU1CiAgcG9ydDogMjQwMDIKICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVD" +
            "c1V3c0ZiQWhVWU1VZ2RlaUMKLSBuYW1lOiBUZXJuLUhUVFBTCiAgdHlwZTogaHR0cAogIHNlcnZl" +
            "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAzCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFz" +
            "c3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdGxzOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QK" +
            "ICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTog" +
            "c2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tSFRUUAogIC0gVGVybi1IVFRQUwpydWxlczoKLSBN" +
            "QVRDSCxHCg=="),
        ("ss", "cHJveGllczoKLSBuYW1lOiBUZXJuLVNTLUFFQUQKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIu" +
            "MTU5LjE1NQogIHBvcnQ6IDI0MDA0CiAgY2lwaGVyOiBhZXMtMjU2LWdjbQogIHBhc3N3b3JkOiBL" +
            "MEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJuLVNTMjAyMgog" +
            "IHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMDUKICBjaXBoZXI6" +
            "IDIwMjItYmxha2UzLWFlcy0xMjgtZ2NtCiAgcGFzc3dvcmQ6IGEyK0lnVExtbnRyazZjSWVGNlVB" +
            "Rnc9PQogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4tU1MtU2hhZG93VExTCiAgdHlwZTogc3MKICBz" +
            "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwNgogIGNpcGhlcjogYWVzLTEyOC1nY20K" +
            "ICBwYXNzd29yZDogU0FJMUcxSGk5SU1XeFQ4ajFkWXN0MFJxCiAgdWRwOiBmYWxzZQogIHBsdWdp" +
            "bjogc2hhZG93LXRscwogIGNsaWVudC1maW5nZXJwcmludDogY2hyb21lCiAgcGx1Z2luLW9wdHM6" +
            "CiAgICBob3N0OiB3d3cubWljcm9zb2Z0LmNvbQogICAgcGFzc3dvcmQ6IG8xMkQzWUY3WW1seERM" +
            "TE5sVERXCiAgICB2ZXJzaW9uOiAzCi0gbmFtZTogVGVybi1TUy1PYmZzCiAgdHlwZTogc3MKICBz" +
            "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyMQogIGNpcGhlcjogYWVzLTI1Ni1nY20K" +
            "ICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdp" +
            "bjogb2JmcwogIHBsdWdpbi1vcHRzOgogICAgbW9kZTogaHR0cAogICAgaG9zdDogd3d3LmJpbmcu" +
            "Y29tCi0gbmFtZTogVGVybi1TUy1WMnJheQogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTku" +
            "MTU1CiAgcG9ydDogMjQwMjIKICBjaXBoZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0" +
            "OHJnM09Oa0s2Zjk3SVNsUW5LcQogIHVkcDogZmFsc2UKICBwbHVnaW46IHYycmF5LXBsdWdpbgog" +
            "IHBsdWdpbi1vcHRzOgogICAgbW9kZTogd2Vic29ja2V0CiAgICBob3N0OiB0ZXJuLnRlc3QKICAg" +
            "IHBhdGg6IC95NTY2eXEydAotIG5hbWU6IFRlcm4tU1MtS0NQVHVuCiAgdHlwZTogc3MKICBzZXJ2" +
            "ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyMwogIGNpcGhlcjogYWVzLTI1Ni1nY20KICBw" +
            "YXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdpbjog" +
            "a2NwdHVuCiAgcGx1Z2luLW9wdHM6CiAgICBrZXk6IEhKOEFmWTRqQnY2d2NEMFhmMjIwCiAgICBj" +
            "cnlwdDogYWVzCiAgICBtb2RlOiBmYXN0CiAgICBub2NvbXA6IHRydWUKICAgIHNtdXh2ZXI6IDEK" +
            "ICAgIGRhdGFzaGFyZDogMTAKICAgIHBhcml0eXNoYXJkOiAzCiAgICBtdHU6IDEzNTAKICAgIHNu" +
            "ZHduZDogMTAyNAogICAgcmN2d25kOiAxMDI0Ci0gbmFtZTogVGVybi1TUy1DbG9hawogIHR5cGU6" +
            "IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMjQKICBjaXBoZXI6IGFlcy0y" +
            "NTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcQogIHVkcDogZmFsc2UK" +
            "ICBwbHVnaW46IGNsb2FrCiAgcGx1Z2luLW9wdHM6CiAgICBVSUQ6IEtDVy9Zb1JWNEorRkpEN2Fr" +
            "WGFhcUE9PQogICAgUHVibGljS2V5OiB1dURuZTlLWlhZcnQzLzFZbHNrTnpwRk01aTFvUk9OQVMz" +
            "b0RKUDk4dmtvPQogICAgU2VydmVyTmFtZTogd3d3LmJpbmcuY29tCiAgICBFbmNyeXB0aW9uTWV0" +
            "aG9kOiBwbGFpbgogICAgQnJvd3NlclNpZzogY2hyb21lCiAgICBOdW1Db25uOiA0CiAgICBQcm94" +
            "eU1ldGhvZDogc2hhZG93c29ja3MKLSBuYW1lOiBUZXJuLVNTLVJlc3RscwogIHR5cGU6IHNzCiAg" +
            "c2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMjUKICBjaXBoZXI6IGFlcy0yNTYtZ2Nt" +
            "CiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcQogIHVkcDogZmFsc2UKICBwbHVn" +
            "aW46IHJlc3RscwogIGNsaWVudC1maW5nZXJwcmludDogY2hyb21lCiAgcGx1Z2luLW9wdHM6CiAg" +
            "ICBob3N0OiB3d3cubWljcm9zb2Z0LmNvbQogICAgcGFzc3dvcmQ6IFA0bmF4NlFvckMzeUppbnZU" +
            "MGFXCiAgICB2ZXJzaW9uLWhpbnQ6IHRsczEzCiAgICByZXN0bHMtc2NyaXB0OiAzMDA/MTAwLDQw" +
            "MH4xMDAsMzUwfjEwMCw2MDB+MTAwLDMwMH4yMDAsMzAwfjEwMApwcm94eS1ncm91cHM6Ci0gbmFt" +
            "ZTogRwogIHR5cGU6IHNlbGVjdAogIHByb3hpZXM6CiAgLSBUZXJuLVNTLUFFQUQKICAtIFRlcm4t" +
            "U1MyMDIyCiAgLSBUZXJuLVNTLVNoYWRvd1RMUwogIC0gVGVybi1TUy1PYmZzCiAgLSBUZXJuLVNT" +
            "LVYycmF5CiAgLSBUZXJuLVNTLUtDUFR1bgogIC0gVGVybi1TUy1DbG9hawogIC0gVGVybi1TUy1S" +
            "ZXN0bHMKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("vmess", "cHJveGllczoKLSBuYW1lOiBUZXJuLVZNZXNzCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1Ljky" +
            "LjE1OS4xNTUKICBwb3J0OiAyNDAwNwogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYx" +
            "ZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB0Y3AKICB1" +
            "ZHA6IHRydWUKLSBuYW1lOiBUZXJuLVZNZXNzLVdTCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1" +
            "LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwOAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4" +
            "LTYxZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB3cwog" +
            "IHVkcDogdHJ1ZQogIHdzLW9wdHM6CiAgICBwYXRoOiAveTlkZ2xtNXUKICAgIGhlYWRlcnM6CiAg" +
            "ICAgIEhvc3Q6IHRlcm4udGVzdApwcm94eS1ncm91cHM6Ci0gbmFtZTogRwogIHR5cGU6IHNlbGVj" +
            "dAogIHByb3hpZXM6CiAgLSBUZXJuLVZNZXNzCiAgLSBUZXJuLVZNZXNzLVdTCnJ1bGVzOgotIE1B" +
            "VENILEcK"),
        ("vless", "cHJveGllczoKLSBuYW1lOiBUZXJuLVZMRVNTCiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6IDQ1Ljky" +
            "LjE1OS4xNTUKICBwb3J0OiAyNDAwOQogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYx" +
            "ZWU2ZmYzYWU3MQogIG5ldHdvcms6IHRjcAogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4tVkxFU1Mt" +
            "UmVhbGl0eQogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQw" +
            "MTAKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02MWVlNmZmM2FlNzEKICBuZXR3b3Jr" +
            "OiB0Y3AKICB1ZHA6IHRydWUKICB0bHM6IHRydWUKICBmbG93OiB4dGxzLXJwcngtdmlzaW9uCiAg" +
            "c2VydmVybmFtZTogd3d3Lm1pY3Jvc29mdC5jb20KICBjbGllbnQtZmluZ2VycHJpbnQ6IGNocm9t" +
            "ZQogIHJlYWxpdHktb3B0czoKICAgIHB1YmxpYy1rZXk6IFdwNlBqVEMzZ2ZjQ0VNUTNwRzBST3Vz" +
            "SGRnQXM3TGZzeDAyM2dmR0RFVlkKICAgIHNob3J0LWlkOiAyMWRkZTNjMzExMmJiYzRiCi0gbmFt" +
            "ZTogVGVybi1WTEVTUy1WaXNpb24KICB0eXBlOiB2bGVzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1" +
            "NQogIHBvcnQ6IDI0MDExCiAgdXVpZDogNmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNh" +
            "ZTcxCiAgbmV0d29yazogdGNwCiAgdWRwOiB0cnVlCiAgdGxzOiB0cnVlCiAgZmxvdzogeHRscy1y" +
            "cHJ4LXZpc2lvbgogIHNlcnZlcm5hbWU6IHRlcm4udGVzdAogIGNsaWVudC1maW5nZXJwcmludDog" +
            "Y2hyb21lCiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tVkxFU1MtTUxLRU0K" +
            "ICB0eXBlOiB2bGVzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDE4CiAgdXVp" +
            "ZDogNmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxCiAgbmV0d29yazogdGNwCiAg" +
            "dWRwOiB0cnVlCiAgZW5jcnlwdGlvbjogbWxrZW03Njh4MjU1MTlwbHVzLm5hdGl2ZS4wcnR0LmJQ" +
            "Szc4UUo5MHdiNkdUMXczQzZXMWswRmNJSHJmclQ2MGdtdkpiZ2RXeGcKcHJveHktZ3JvdXBzOgot" +
            "IG5hbWU6IEcKICB0eXBlOiBzZWxlY3QKICBwcm94aWVzOgogIC0gVGVybi1WTEVTUwogIC0gVGVy" +
            "bi1WTEVTUy1SZWFsaXR5CiAgLSBUZXJuLVZMRVNTLVZpc2lvbgogIC0gVGVybi1WTEVTUy1NTEtF" +
            "TQpydWxlczoKLSBNQVRDSCxHCg=="),
        ("trojan", "cHJveGllczoKLSBuYW1lOiBUZXJuLVRyb2phbgogIHR5cGU6IHRyb2phbgogIHNlcnZlcjogNDUu" +
            "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDEyCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
            "CiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnBy" +
            "b3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4t" +
            "VHJvamFuCnJ1bGVzOgotIE1BVENILEcK"),
        ("hysteria", "cHJveGllczoKLSBuYW1lOiBUZXJuLUh5c3RlcmlhCiAgdHlwZTogaHlzdGVyaWEKICBzZXJ2ZXI6" +
            "IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxMwogIHByb3RvY29sOiB1ZHAKICB1cDogNTAgTWJw" +
            "cwogIGRvd246IDEwMCBNYnBzCiAgYWxwbjoKICAtIGh5c3RlcmlhCiAgdWRwOiB0cnVlCiAgYXV0" +
            "aC1zdHI6IEJKT1N1Y3hqWnNVTEpkbnN5TlBUCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQt" +
            "dmVyaWZ5OiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAgcHJv" +
            "eGllczoKICAtIFRlcm4tSHlzdGVyaWEKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("hysteria2", "cHJveGllczoKLSBuYW1lOiBUZXJuLUh5c3RlcmlhMgogIHR5cGU6IGh5c3RlcmlhMgogIHNlcnZl" +
            "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDE0CiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlN" +
            "VWdkZWlDCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0" +
            "cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAgcHJveGllczoKICAt" +
            "IFRlcm4tSHlzdGVyaWEyCnJ1bGVzOgotIE1BVENILEcK"),
        ("tuic", "cHJveGllczoKLSBuYW1lOiBUZXJuLVRVSUMKICB0eXBlOiB0dWljCiAgc2VydmVyOiA0NS45Mi4x" +
            "NTkuMTU1CiAgcG9ydDogMjQwMTUKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02MWVl" +
            "NmZmM2FlNzEKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICBhbHBuOgogIC0gaDMK" +
            "ICB1ZHA6IHRydWUKICBjb25nZXN0aW9uLWNvbnRyb2xsZXI6IGJicgogIHNuaTogdGVybi50ZXN0" +
            "CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQpwcm94eS1ncm91cHM6Ci0gbmFtZTogRwogIHR5cGU6" +
            "IHNlbGVjdAogIHByb3hpZXM6CiAgLSBUZXJuLVRVSUMKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("anytls", "cHJveGllczoKLSBuYW1lOiBUZXJuLUFueVRMUwogIHR5cGU6IGFueXRscwogIHNlcnZlcjogNDUu" +
            "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDE2CiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
            "CiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnBy" +
            "b3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4t" +
            "QW55VExTCnJ1bGVzOgotIE1BVENILEcK"),
        ("naive", "cHJveGllczoKLSBuYW1lOiBUZXJuLU5haXZlLUgyCiAgdHlwZTogbmFpdmUKICBzZXJ2ZXI6IDQ1" +
            "LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNwogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3Jk" +
            "OiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHF1aWM6IGZhbHNlCiAgdWRwOiB0cnVlCiAgdWRwLW92" +
            "ZXItdGNwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0g" +
            "bmFtZTogVGVybi1OYWl2ZS1IMwogIHR5cGU6IG5haXZlCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1" +
            "CiAgcG9ydDogMjQwMTcKICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0Zi" +
            "QWhVWU1VZ2RlaUMKICBxdWljOiB0cnVlCiAgdWRwOiB0cnVlCiAgdWRwLW92ZXItdGNwOiB0cnVl" +
            "CiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnByb3h5LWdyb3VwczoK" +
            "LSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tTmFpdmUtSDIKICAt" +
            "IFRlcm4tTmFpdmUtSDMKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("ssr", "cHJveGllczoKLSBuYW1lOiBUZXJuLVNTUgogIHR5cGU6IHNzcgogIHNlcnZlcjogNDUuOTIuMTU5" +
            "LjE1NQogIHBvcnQ6IDI0MDI2CiAgY2lwaGVyOiBhZXMtMjU2LWNmYgogIHBhc3N3b3JkOiBvOG5B" +
            "cU12eGx1TDJDdlFvY3dkZwogIHByb3RvY29sOiBhdXRoX2FlczEyOF9tZDUKICBvYmZzOiB0bHMx" +
            "LjJfdGlja2V0X2F1dGgKICB1ZHA6IHRydWUKcHJveHktZ3JvdXBzOgotIG5hbWU6IEcKICB0eXBl" +
            "OiBzZWxlY3QKICBwcm94aWVzOgogIC0gVGVybi1TU1IKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("snell", "cHJveGllczoKLSBuYW1lOiBUZXJuLVNuZWxsNAogIHR5cGU6IHNuZWxsCiAgc2VydmVyOiA0NS45" +
            "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMjcKICBwc2s6IGp5bmg1ejhVNmc1bGN0R0F5VW53RnhZRwog" +
            "IHBhc3N3b3JkOiBqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUcKICB2ZXJzaW9uOiA0CiAgdWRwOiB0" +
            "cnVlCi0gbmFtZTogVGVybi1TbmVsbDUKICB0eXBlOiBzbmVsbAogIHNlcnZlcjogNDUuOTIuMTU5" +
            "LjE1NQogIHBvcnQ6IDI0MDI4CiAgcHNrOiBqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUcKICBwYXNz" +
            "d29yZDoganluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgdmVyc2lvbjogNQogIHVkcDogdHJ1ZQpw" +
            "cm94eS1ncm91cHM6Ci0gbmFtZTogRwogIHR5cGU6IHNlbGVjdAogIHByb3hpZXM6CiAgLSBUZXJu" +
            "LVNuZWxsNAogIC0gVGVybi1TbmVsbDUKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("mieru", "cHJveGllczoKLSBuYW1lOiBUZXJuLU1pZXJ1CiAgdHlwZTogbWllcnUKICBzZXJ2ZXI6IDQ1Ljky" +
            "LjE1OS4xNTUKICBwb3J0OiAyNDAyOQogIHRyYW5zcG9ydDogVENQCiAgdXNlcm5hbWU6IHRlcm5k" +
            "cGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCiAgbXVsdGlw" +
            "bGV4aW5nOiBNVUxUSVBMRVhJTkdfTE9XCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTog" +
            "c2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tTWllcnUKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("ssh", "cHJveGllczoKLSBuYW1lOiBUZXJuLVNTSAogIHR5cGU6IHNzaAogIHNlcnZlcjogNDUuOTIuMTU5" +
            "LjE1NQogIHBvcnQ6IDI0MDMwCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NV" +
            "d3NGYkFoVVlNVWdkZWlDCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAg" +
            "cHJveGllczoKICAtIFRlcm4tU1NICnJ1bGVzOgotIE1BVENILEcK"),
        ("brook", "cHJveGllczoKLSBuYW1lOiBUZXJuLUJyb29rCiAgdHlwZTogYnJvb2sKICBzZXJ2ZXI6IDQ1Ljky" +
            "LjE1OS4xNTUKICBwb3J0OiAyNDAzMQogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwog" +
            "IHRyYW5zcG9ydDogc2VydmVyCiAgdWRwOiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAg" +
            "dHlwZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tQnJvb2sKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("gost-relay", "cHJveGllczoKLSBuYW1lOiBUZXJuLUdPU1QtUmVsYXkKICB0eXBlOiBnb3N0LXJlbGF5CiAgc2Vy" +
            "dmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzIKICB1c2VybmFtZTogdGVybmRwYTMKICBw" +
            "YXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB0bHM6IHRydWUKICB1ZHA6IHRydWUKICBz" +
            "bmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKcHJveHktZ3JvdXBzOgotIG5h" +
            "bWU6IEcKICB0eXBlOiBzZWxlY3QKICBwcm94aWVzOgogIC0gVGVybi1HT1NULVJlbGF5CnJ1bGVz" +
            "OgotIE1BVENILEcK"),
        ("juicity", "cHJveGllczoKLSBuYW1lOiBUZXJuLUp1aWNpdHkKICB0eXBlOiBqdWljaXR5CiAgc2VydmVyOiA0" +
            "NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzMKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0" +
            "OC02MWVlNmZmM2FlNzEKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRy" +
            "dWUKICBjb25nZXN0aW9uLWNvbnRyb2xsZXI6IGJicgogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1j" +
            "ZXJ0LXZlcmlmeTogdHJ1ZQpwcm94eS1ncm91cHM6Ci0gbmFtZTogRwogIHR5cGU6IHNlbGVjdAog" +
            "IHByb3hpZXM6CiAgLSBUZXJuLUp1aWNpdHkKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("wireguard", "cHJveGllczoKLSBuYW1lOiBUZXJuLVdpcmVHdWFyZAogIHR5cGU6IHdpcmVndWFyZAogIHNlcnZl" +
            "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDM0CiAgaXA6IDEwLjY2LjAuMgogIHVkcDogdHJ1" +
            "ZQogIG10dTogMTI4MAogIGRuczoKICAtIDEuMS4xLjEKICBwcml2YXRlLWtleTogT0pWUWNBUXVt" +
            "bE5pQURCeWpGMDNiRXFscTVqSEZOMmszREZOMEJhRS9Fbz0KICBwdWJsaWMta2V5OiBwRHVIZ3JS" +
            "dUkwcldkb2dybmRad3V5ci9ENjhwVURvazFGYlhQOVJrMFgwPQogIHJlbW90ZS1kbnMtcmVzb2x2" +
            "ZTogdHJ1ZQotIG5hbWU6IFRlcm4tQW1uZXppYVdHCiAgdHlwZTogd2lyZWd1YXJkCiAgc2VydmVy" +
            "OiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzUKICBpcDogMTAuNjcuMC4yCiAgdWRwOiB0cnVl" +
            "CiAgbXR1OiAxMjgwCiAgZG5zOgogIC0gMS4xLjEuMQogIHByaXZhdGUta2V5OiBTRVZmOFhlL3hR" +
            "alZ0RHRzN3pDc0tnSDVNbzE0alQ5SVUzeEFxbW8wT1VNPQogIHB1YmxpYy1rZXk6IGdxejlSdm1J" +
            "eXVwQWczdzI1eVAvNW40U2FZc2g5VjFJaHI4ZVRta0pmRFE9CiAgcmVtb3RlLWRucy1yZXNvbHZl" +
            "OiB0cnVlCiAgYW1uZXppYS13Zy1vcHRpb246CiAgICBqYzogNAogICAgam1pbjogNDAKICAgIGpt" +
            "YXg6IDcwCiAgICBzMTogMjkKICAgIHMyOiA1NgogICAgaDE6IDYxMDg5ODE1MQogICAgaDI6IDEy" +
            "ODU5ODEwODQKICAgIGgzOiAxNzY3NTE3NzMxCiAgICBoNDogMTk5NTMwNDY1MApwcm94eS1ncm91" +
            "cHM6Ci0gbmFtZTogRwogIHR5cGU6IHNlbGVjdAogIHByb3hpZXM6CiAgLSBUZXJuLVdpcmVHdWFy" +
            "ZAogIC0gVGVybi1BbW5lemlhV0cKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("openconnect", "cHJveGllczoKLSBuYW1lOiBUZXJuLU9wZW5Db25uZWN0CiAgdHlwZTogb3BlbmNvbm5lY3QKICBz" +
            "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzNgogIHVzZXJuYW1lOiB0ZXJuZHBhMwog" +
            "IHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIGR0bHM6IHRydWUKICB1ZHA6IHRydWUK" +
            "ICBzbmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKcHJveHktZ3JvdXBzOgot" +
            "IG5hbWU6IEcKICB0eXBlOiBzZWxlY3QKICBwcm94aWVzOgogIC0gVGVybi1PcGVuQ29ubmVjdApy" +
            "dWxlczoKLSBNQVRDSCxHCg=="),
        ("trusttunnel", "cHJveGllczoKLSBuYW1lOiBUZXJuLVRydXN0VHVubmVsLUgyCiAgdHlwZTogdHJ1c3R0dW5uZWwK" +
            "ICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzNwogIHVzZXJuYW1lOiB0ZXJuZHBh" +
            "MwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHF1aWM6IGZhbHNlCiAgdWRwOiB0" +
            "cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVy" +
            "bi1UcnVzdFR1bm5lbC1IMwogIHR5cGU6IHRydXN0dHVubmVsCiAgc2VydmVyOiA0NS45Mi4xNTku" +
            "MTU1CiAgcG9ydDogMjQwMzcKICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3" +
            "c0ZiQWhVWU1VZ2RlaUMKICBxdWljOiB0cnVlCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QK" +
            "ICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTog" +
            "c2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tVHJ1c3RUdW5uZWwtSDIKICAtIFRlcm4tVHJ1c3RU" +
            "dW5uZWwtSDMKcnVsZXM6Ci0gTUFUQ0gsRwo="),
        ("sudoku", "cHJveGllczoKLSBuYW1lOiBUZXJuLVN1ZG9rdQogIHR5cGU6IHN1ZG9rdQogIHNlcnZlcjogNDUu" +
            "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDM4CiAga2V5OiAzYzdiZjBmM2VlZGFlMGJlNjY2NjRiMmI5" +
            "MDQ3ZjU0ZDg5Yzc0ZGYwMzQ3NThiMzVhZTkzNTlhNDFjNGY1ZDBlNmUwMjI5NTEwMzQ5NzY4NmFi" +
            "NTY2MzM4YzA2ZmRmN2IxOWFjMGI1MGMwNjhhMmE0MWY1ZjZmNTE3NmRhZTQwMgogIGFlYWQtbWV0" +
            "aG9kOiBjaGFjaGEyMC1wb2x5MTMwNQogIHRhYmxlLXR5cGU6IHByZWZlcl9lbnRyb3B5CnByb3h5" +
            "LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlwZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tU3Vk" +
            "b2t1CnJ1bGVzOgotIE1BVENILEcK"),
        ("masque", "cHJveGllczoKLSBuYW1lOiBUZXJuLU1BU1FVRS1JUAogIHR5cGU6IG1hc3F1ZQogIHNlcnZlcjog" +
            "NDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDM5CiAgbW9kZTogY29ubmVjdC1pcAogIHVyaTogaHR0" +
            "cHM6Ly9wcm94eToyNDAzOS92cG4KICBzbmk6IHByb3h5CiAgbXR1OiAxMjAwCiAgZG5zOgogIC0g" +
            "MS4xLjEuMQogIHVkcDogdHJ1ZQogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJu" +
            "LU1BU1FVRS1VRFAKICB0eXBlOiBtYXNxdWUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
            "OiAyNDA0MAogIG1vZGU6IGNvbm5lY3QtdWRwCiAgdXNlcm5hbWU6IHRlcm4KICBwYXNzd29yZDog" +
            "dGVybgogIHVyaTogaHR0cHM6Ly90ZXJuLnRlc3Q6MjQwNDAvLndlbGwta25vd24vbWFzcXVlL3Vk" +
            "cC97dGFyZ2V0X2hvc3R9L3t0YXJnZXRfcG9ydH0vCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRl" +
            "c3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBHCiAgdHlw" +
            "ZTogc2VsZWN0CiAgcHJveGllczoKICAtIFRlcm4tTUFTUVVFLUlQCiAgLSBUZXJuLU1BU1FVRS1V" +
            "RFAKcnVsZXM6Ci0gTUFUQ0gsRwo="),
    ]

    static let fullMinusOpenConnectB64 =
            "cHJveGllczoKLSBuYW1lOiBUZXJuLVNPQ0tTNQogIHR5cGU6IHNvY2tzNQogIHNlcnZlcjogNDUu" +
            "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAxCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6" +
            "IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCi0gbmFtZTogVGVybi1IVFRQCiAgdHlw" +
            "ZTogaHR0cAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAyCiAgdXNlcm5hbWU6" +
            "IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCi0gbmFtZTogVGVybi1I" +
            "VFRQUwogIHR5cGU6IGh0dHAKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwMwog" +
            "IHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHRs" +
            "czogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6" +
            "IFRlcm4tU1MtQUVBRAogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDog" +
            "MjQwMDQKICBjaXBoZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3" +
            "SVNsUW5LcQogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4tU1MyMDIyCiAgdHlwZTogc3MKICBzZXJ2" +
            "ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwNQogIGNpcGhlcjogMjAyMi1ibGFrZTMtYWVz" +
            "LTEyOC1nY20KICBwYXNzd29yZDogYTIrSWdUTG1udHJrNmNJZUY2VUFGdz09CiAgdWRwOiB0cnVl" +
            "Ci0gbmFtZTogVGVybi1TUy1TaGFkb3dUTFMKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5" +
            "LjE1NQogIHBvcnQ6IDI0MDA2CiAgY2lwaGVyOiBhZXMtMTI4LWdjbQogIHBhc3N3b3JkOiBTQUkx" +
            "RzFIaTlJTVd4VDhqMWRZc3QwUnEKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBzaGFkb3ctdGxzCiAg" +
            "Y2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAgIGhvc3Q6IHd3dy5t" +
            "aWNyb3NvZnQuY29tCiAgICBwYXNzd29yZDogbzEyRDNZRjdZbWx4RExMTmxURFcKICAgIHZlcnNp" +
            "b246IDMKLSBuYW1lOiBUZXJuLVZNZXNzCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1" +
            "OS4xNTUKICBwb3J0OiAyNDAwNwogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2" +
            "ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB0Y3AKICB1ZHA6" +
            "IHRydWUKLSBuYW1lOiBUZXJuLVZNZXNzLVdTCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1Ljky" +
            "LjE1OS4xNTUKICBwb3J0OiAyNDAwOAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYx" +
            "ZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB3cwogIHVk" +
            "cDogdHJ1ZQogIHdzLW9wdHM6CiAgICBwYXRoOiAveTlkZ2xtNXUKICAgIGhlYWRlcnM6CiAgICAg" +
            "IEhvc3Q6IHRlcm4udGVzdAotIG5hbWU6IFRlcm4tVkxFU1MKICB0eXBlOiB2bGVzcwogIHNlcnZl" +
            "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDA5CiAgdXVpZDogNmNlYjUyMTUtMTViOS00ZWYz" +
            "LThhNDgtNjFlZTZmZjNhZTcxCiAgbmV0d29yazogdGNwCiAgdWRwOiB0cnVlCi0gbmFtZTogVGVy" +
            "bi1WTEVTUy1SZWFsaXR5CiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBw" +
            "b3J0OiAyNDAxMAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQog" +
            "IG5ldHdvcms6IHRjcAogIHVkcDogdHJ1ZQogIHRsczogdHJ1ZQogIGZsb3c6IHh0bHMtcnByeC12" +
            "aXNpb24KICBzZXJ2ZXJuYW1lOiB3d3cubWljcm9zb2Z0LmNvbQogIGNsaWVudC1maW5nZXJwcmlu" +
            "dDogY2hyb21lCiAgcmVhbGl0eS1vcHRzOgogICAgcHVibGljLWtleTogV3A2UGpUQzNnZmNDRU1R" +
            "M3BHMFJPdXNIZGdBczdMZnN4MDIzZ2ZHREVWWQogICAgc2hvcnQtaWQ6IDIxZGRlM2MzMTEyYmJj" +
            "NGIKLSBuYW1lOiBUZXJuLVZMRVNTLVZpc2lvbgogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45" +
            "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMTEKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02" +
            "MWVlNmZmM2FlNzEKICBuZXR3b3JrOiB0Y3AKICB1ZHA6IHRydWUKICB0bHM6IHRydWUKICBmbG93" +
            "OiB4dGxzLXJwcngtdmlzaW9uCiAgc2VydmVybmFtZTogdGVybi50ZXN0CiAgY2xpZW50LWZpbmdl" +
            "cnByaW50OiBjaHJvbWUKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1WTEVT" +
            "Uy1NTEtFTQogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQw" +
            "MTgKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02MWVlNmZmM2FlNzEKICBuZXR3b3Jr" +
            "OiB0Y3AKICB1ZHA6IHRydWUKICBlbmNyeXB0aW9uOiBtbGtlbTc2OHgyNTUxOXBsdXMubmF0aXZl" +
            "LjBydHQuYlBLNzhRSjkwd2I2R1QxdzNDNlcxazBGY0lIcmZyVDYwZ212SmJnZFd4ZwotIG5hbWU6" +
            "IFRlcm4tVHJvamFuCiAgdHlwZTogdHJvamFuCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9y" +
            "dDogMjQwMTIKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUKICBz" +
            "bmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLUh5c3Rl" +
            "cmlhCiAgdHlwZTogaHlzdGVyaWEKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAx" +
            "MwogIHByb3RvY29sOiB1ZHAKICB1cDogNTAgTWJwcwogIGRvd246IDEwMCBNYnBzCiAgYWxwbjoK" +
            "ICAtIGh5c3RlcmlhCiAgdWRwOiB0cnVlCiAgYXV0aC1zdHI6IEJKT1N1Y3hqWnNVTEpkbnN5TlBU" +
            "CiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1I" +
            "eXN0ZXJpYTIKICB0eXBlOiBoeXN0ZXJpYTIKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
            "OiAyNDAxNAogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1ZQogIHNu" +
            "aTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tVFVJQwog" +
            "IHR5cGU6IHR1aWMKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNQogIHV1aWQ6" +
            "IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIHBhc3N3b3JkOiB5ZUNzVXdz" +
            "RmJBaFVZTVVnZGVpQwogIGFscG46CiAgLSBoMwogIHVkcDogdHJ1ZQogIGNvbmdlc3Rpb24tY29u" +
            "dHJvbGxlcjogYmJyCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0g" +
            "bmFtZTogVGVybi1BbnlUTFMKICB0eXBlOiBhbnl0bHMKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
            "ICBwb3J0OiAyNDAxNgogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1" +
            "ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4t" +
            "TmFpdmUtSDIKICB0eXBlOiBuYWl2ZQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0" +
            "MDE3CiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
            "CiAgcXVpYzogZmFsc2UKICB1ZHA6IHRydWUKICB1ZHAtb3Zlci10Y3A6IHRydWUKICBzbmk6IHRl" +
            "cm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLU5haXZlLUgzCiAg" +
            "dHlwZTogbmFpdmUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNwogIHVzZXJu" +
            "YW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHF1aWM6IHRy" +
            "dWUKICB1ZHA6IHRydWUKICB1ZHAtb3Zlci10Y3A6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNr" +
            "aXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLVNTLU9iZnMKICB0eXBlOiBzcwogIHNl" +
            "cnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIxCiAgY2lwaGVyOiBhZXMtMjU2LWdjbQog" +
            "IHBhc3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2lu" +
            "OiBvYmZzCiAgcGx1Z2luLW9wdHM6CiAgICBtb2RlOiBodHRwCiAgICBob3N0OiB3d3cuYmluZy5j" +
            "b20KLSBuYW1lOiBUZXJuLVNTLVYycmF5CiAgdHlwZTogc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4x" +
            "NTUKICBwb3J0OiAyNDAyMgogIGNpcGhlcjogYWVzLTI1Ni1nY20KICBwYXNzd29yZDogSzBBbHQ4" +
            "cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdpbjogdjJyYXktcGx1Z2luCiAg" +
            "cGx1Z2luLW9wdHM6CiAgICBtb2RlOiB3ZWJzb2NrZXQKICAgIGhvc3Q6IHRlcm4udGVzdAogICAg" +
            "cGF0aDogL3k1NjZ5cTJ0Ci0gbmFtZTogVGVybi1TUy1LQ1BUdW4KICB0eXBlOiBzcwogIHNlcnZl" +
            "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIzCiAgY2lwaGVyOiBhZXMtMjU2LWdjbQogIHBh" +
            "c3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBr" +
            "Y3B0dW4KICBwbHVnaW4tb3B0czoKICAgIGtleTogSEo4QWZZNGpCdjZ3Y0QwWGYyMjAKICAgIGNy" +
            "eXB0OiBhZXMKICAgIG1vZGU6IGZhc3QKICAgIG5vY29tcDogdHJ1ZQogICAgc211eHZlcjogMQog" +
            "ICAgZGF0YXNoYXJkOiAxMAogICAgcGFyaXR5c2hhcmQ6IDMKICAgIG10dTogMTM1MAogICAgc25k" +
            "d25kOiAxMDI0CiAgICByY3Z3bmQ6IDEwMjQKLSBuYW1lOiBUZXJuLVNTLUNsb2FrCiAgdHlwZTog" +
            "c3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNAogIGNpcGhlcjogYWVzLTI1" +
            "Ni1nY20KICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQog" +
            "IHBsdWdpbjogY2xvYWsKICBwbHVnaW4tb3B0czoKICAgIFVJRDogS0NXL1lvUlY0SitGSkQ3YWtY" +
            "YWFxQT09CiAgICBQdWJsaWNLZXk6IHV1RG5lOUtaWFlydDMvMVlsc2tOenBGTTVpMW9ST05BUzNv" +
            "REpQOTh2a289CiAgICBTZXJ2ZXJOYW1lOiB3d3cuYmluZy5jb20KICAgIEVuY3J5cHRpb25NZXRo" +
            "b2Q6IHBsYWluCiAgICBCcm93c2VyU2lnOiBjaHJvbWUKICAgIE51bUNvbm46IDQKICAgIFByb3h5" +
            "TWV0aG9kOiBzaGFkb3dzb2NrcwotIG5hbWU6IFRlcm4tU1MtUmVzdGxzCiAgdHlwZTogc3MKICBz" +
            "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNQogIGNpcGhlcjogYWVzLTI1Ni1nY20K" +
            "ICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdp" +
            "bjogcmVzdGxzCiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAg" +
            "IGhvc3Q6IHd3dy5taWNyb3NvZnQuY29tCiAgICBwYXNzd29yZDogUDRuYXg2UW9yQzN5SmludlQw" +
            "YVcKICAgIHZlcnNpb24taGludDogdGxzMTMKICAgIHJlc3Rscy1zY3JpcHQ6IDMwMD8xMDAsNDAw" +
            "fjEwMCwzNTB+MTAwLDYwMH4xMDAsMzAwfjIwMCwzMDB+MTAwCi0gbmFtZTogVGVybi1TU1IKICB0" +
            "eXBlOiBzc3IKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNgogIGNpcGhlcjog" +
            "YWVzLTI1Ni1jZmIKICBwYXNzd29yZDogbzhuQXFNdnhsdUwyQ3ZRb2N3ZGcKICBwcm90b2NvbDog" +
            "YXV0aF9hZXMxMjhfbWQ1CiAgb2JmczogdGxzMS4yX3RpY2tldF9hdXRoCiAgdWRwOiB0cnVlCi0g" +
            "bmFtZTogVGVybi1TbmVsbDQKICB0eXBlOiBzbmVsbAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQog" +
            "IHBvcnQ6IDI0MDI3CiAgcHNrOiBqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUcKICBwYXNzd29yZDog" +
            "anluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgdmVyc2lvbjogNAogIHVkcDogdHJ1ZQotIG5hbWU6" +
            "IFRlcm4tU25lbGw1CiAgdHlwZTogc25lbGwKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
            "OiAyNDAyOAogIHBzazoganluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgcGFzc3dvcmQ6IGp5bmg1" +
            "ejhVNmc1bGN0R0F5VW53RnhZRwogIHZlcnNpb246IDUKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJu" +
            "LU1pZXJ1CiAgdHlwZTogbWllcnUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAy" +
            "OQogIHRyYW5zcG9ydDogVENQCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NV" +
            "d3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCiAgbXVsdGlwbGV4aW5nOiBNVUxUSVBMRVhJTkdf" +
            "TE9XCi0gbmFtZTogVGVybi1TU0gKICB0eXBlOiBzc2gKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
            "ICBwb3J0OiAyNDAzMAogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJB" +
            "aFVZTVVnZGVpQwotIG5hbWU6IFRlcm4tQnJvb2sKICB0eXBlOiBicm9vawogIHNlcnZlcjogNDUu" +
            "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDMxCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
            "CiAgdHJhbnNwb3J0OiBzZXJ2ZXIKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJuLUdPU1QtUmVsYXkK" +
            "ICB0eXBlOiBnb3N0LXJlbGF5CiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzIK" +
            "ICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB0" +
            "bHM6IHRydWUKICB1ZHA6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6" +
            "IHRydWUKLSBuYW1lOiBUZXJuLUp1aWNpdHkKICB0eXBlOiBqdWljaXR5CiAgc2VydmVyOiA0NS45" +
            "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzMKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02" +
            "MWVlNmZmM2FlNzEKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUK" +
            "ICBjb25nZXN0aW9uLWNvbnRyb2xsZXI6IGJicgogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0" +
            "LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tV2lyZUd1YXJkCiAgdHlwZTogd2lyZWd1YXJkCiAg" +
            "c2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzQKICBpcDogMTAuNjYuMC4yCiAgdWRw" +
            "OiB0cnVlCiAgbXR1OiAxMjgwCiAgZG5zOgogIC0gMS4xLjEuMQogIHByaXZhdGUta2V5OiBPSlZR" +
            "Y0FRdW1sTmlBREJ5akYwM2JFcWxxNWpIRk4yazNERk4wQmFFL0VvPQogIHB1YmxpYy1rZXk6IHBE" +
            "dUhnclJ1STByV2RvZ3JuZFp3dXlyL0Q2OHBVRG9rMUZiWFA5UmswWDA9CiAgcmVtb3RlLWRucy1y" +
            "ZXNvbHZlOiB0cnVlCi0gbmFtZTogVGVybi1BbW5lemlhV0cKICB0eXBlOiB3aXJlZ3VhcmQKICBz" +
            "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzNQogIGlwOiAxMC42Ny4wLjIKICB1ZHA6" +
            "IHRydWUKICBtdHU6IDEyODAKICBkbnM6CiAgLSAxLjEuMS4xCiAgcHJpdmF0ZS1rZXk6IFNFVmY4" +
            "WGUveFFqVnREdHM3ekNzS2dINU1vMTRqVDlJVTN4QXFtbzBPVU09CiAgcHVibGljLWtleTogZ3F6" +
            "OVJ2bUl5dXBBZzN3MjV5UC81bjRTYVlzaDlWMUlocjhlVG1rSmZEUT0KICByZW1vdGUtZG5zLXJl" +
            "c29sdmU6IHRydWUKICBhbW5lemlhLXdnLW9wdGlvbjoKICAgIGpjOiA0CiAgICBqbWluOiA0MAog" +
            "ICAgam1heDogNzAKICAgIHMxOiAyOQogICAgczI6IDU2CiAgICBoMTogNjEwODk4MTUxCiAgICBo" +
            "MjogMTI4NTk4MTA4NAogICAgaDM6IDE3Njc1MTc3MzEKICAgIGg0OiAxOTk1MzA0NjUwCi0gbmFt" +
            "ZTogVGVybi1UcnVzdFR1bm5lbC1IMgogIHR5cGU6IHRydXN0dHVubmVsCiAgc2VydmVyOiA0NS45" +
            "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzcKICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDog" +
            "eWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICBxdWljOiBmYWxzZQogIHVkcDogdHJ1ZQogIHNuaTogdGVy" +
            "bi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tVHJ1c3RUdW5uZWwt" +
            "SDMKICB0eXBlOiB0cnVzdHR1bm5lbAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0" +
            "MDM3CiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
            "CiAgcXVpYzogdHJ1ZQogIHVkcDogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZl" +
            "cmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tU3Vkb2t1CiAgdHlwZTogc3Vkb2t1CiAgc2VydmVyOiA0" +
            "NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzgKICBrZXk6IDNjN2JmMGYzZWVkYWUwYmU2NjY2NGIy" +
            "YjkwNDdmNTRkODljNzRkZjAzNDc1OGIzNWFlOTM1OWE0MWM0ZjVkMGU2ZTAyMjk1MTAzNDk3Njg2" +
            "YWI1NjYzMzhjMDZmZGY3YjE5YWMwYjUwYzA2OGEyYTQxZjVmNmY1MTc2ZGFlNDAyCiAgYWVhZC1t" +
            "ZXRob2Q6IGNoYWNoYTIwLXBvbHkxMzA1CiAgdGFibGUtdHlwZTogcHJlZmVyX2VudHJvcHkKLSBu" +
            "YW1lOiBUZXJuLU1BU1FVRS1JUAogIHR5cGU6IG1hc3F1ZQogIHNlcnZlcjogNDUuOTIuMTU5LjE1" +
            "NQogIHBvcnQ6IDI0MDM5CiAgbW9kZTogY29ubmVjdC1pcAogIHVyaTogaHR0cHM6Ly9wcm94eToy" +
            "NDAzOS92cG4KICBzbmk6IHByb3h5CiAgbXR1OiAxMjAwCiAgZG5zOgogIC0gMS4xLjEuMQogIHVk" +
            "cDogdHJ1ZQogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLU1BU1FVRS1VRFAK" +
            "ICB0eXBlOiBtYXNxdWUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDA0MAogIG1v" +
            "ZGU6IGNvbm5lY3QtdWRwCiAgdXNlcm5hbWU6IHRlcm4KICBwYXNzd29yZDogdGVybgogIHVyaTog" +
            "aHR0cHM6Ly90ZXJuLnRlc3Q6MjQwNDAvLndlbGwta25vd24vbWFzcXVlL3VkcC97dGFyZ2V0X2hv" +
            "c3R9L3t0YXJnZXRfcG9ydH0vCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNl" +
            "cnQtdmVyaWZ5OiB0cnVlCnByb3h5LWdyb3VwczoKLSBuYW1lOiBUZXJuLVRlc3QKICB0eXBlOiBz" +
            "ZWxlY3QKICBwcm94aWVzOgogIC0gVGVybi1TT0NLUzUKICAtIFRlcm4tSFRUUAogIC0gVGVybi1I" +
            "VFRQUwogIC0gVGVybi1TUy1BRUFECiAgLSBUZXJuLVNTMjAyMgogIC0gVGVybi1TUy1TaGFkb3dU" +
            "TFMKICAtIFRlcm4tVk1lc3MKICAtIFRlcm4tVk1lc3MtV1MKICAtIFRlcm4tVkxFU1MKICAtIFRl" +
            "cm4tVkxFU1MtUmVhbGl0eQogIC0gVGVybi1WTEVTUy1WaXNpb24KICAtIFRlcm4tVkxFU1MtTUxL" +
            "RU0KICAtIFRlcm4tVHJvamFuCiAgLSBUZXJuLUh5c3RlcmlhCiAgLSBUZXJuLUh5c3RlcmlhMgog" +
            "IC0gVGVybi1UVUlDCiAgLSBUZXJuLUFueVRMUwogIC0gVGVybi1OYWl2ZS1IMgogIC0gVGVybi1O" +
            "YWl2ZS1IMwogIC0gVGVybi1TUy1PYmZzCiAgLSBUZXJuLVNTLVYycmF5CiAgLSBUZXJuLVNTLUtD" +
            "UFR1bgogIC0gVGVybi1TUy1DbG9hawogIC0gVGVybi1TUy1SZXN0bHMKICAtIFRlcm4tU1NSCiAg" +
            "LSBUZXJuLVNuZWxsNAogIC0gVGVybi1TbmVsbDUKICAtIFRlcm4tTWllcnUKICAtIFRlcm4tU1NI" +
            "CiAgLSBUZXJuLUJyb29rCiAgLSBUZXJuLUdPU1QtUmVsYXkKICAtIFRlcm4tSnVpY2l0eQogIC0g" +
            "VGVybi1XaXJlR3VhcmQKICAtIFRlcm4tQW1uZXppYVdHCiAgLSBUZXJuLVRydXN0VHVubmVsLUgy" +
            "CiAgLSBUZXJuLVRydXN0VHVubmVsLUgzCiAgLSBUZXJuLVN1ZG9rdQogIC0gVGVybi1NQVNRVUUt" +
            "SVAKICAtIFRlcm4tTUFTUVVFLVVEUApydWxlczoKLSBNQVRDSCxUZXJuLVRlc3QK"

    func testKitImportDiagnosis() async {
        var report = ""
        func check(_ label: String, _ b64: String) async {
            guard let data = Data(base64Encoded: b64), let text = String(data: data, encoding: .utf8) else {
                report += "\(label): <base64 decode failed>\n"
                return
            }
            let err = await ProfileStore.validate(text: text)
            report += "\(label): \(err ?? "OK")\n"
        }
        await check("FULL", UITestSeed.kitProbeB64)
        await check("FULL-MINUS-OPENCONNECT", Self.fullMinusOpenConnectB64)
        await check("REDUCED", UITestSeed.kitProbeReducedB64)
        for (t, b64) in Self.subsets { await check("type:" + t, b64) }
        print(report)
        let att = XCTAttachment(string: report)
        att.name = "kit-import-diagnosis"
        att.lifetime = .keepAlways
        add(att)
    }
}
