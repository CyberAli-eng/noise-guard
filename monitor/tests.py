from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from django.urls import reverse

from .models import Alert


class AlertModelTests(TestCase):
    def test_str_includes_ip_and_status(self):
        alert = Alert.objects.create(ip_address="10.0.0.5", packet_size=1600, status="Suspicious")
        self.assertIn("10.0.0.5", str(alert))
        self.assertIn("Suspicious", str(alert))


class LoginRequiredTests(TestCase):
    def test_every_view_redirects_anonymous_users_to_login(self):
        alert = Alert.objects.create(ip_address="10.0.0.5", packet_size=100, status="Safe")
        urls = [
            reverse("dashboard"),
            reverse("unblock_alert", args=[alert.id]),
            reverse("delete_alert", args=[alert.id]),
            reverse("export_csv"),
            reverse("export_pdf"),
        ]
        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login/", response["Location"])
        # nothing was changed by the anonymous requests
        self.assertTrue(Alert.objects.filter(id=alert.id).exists())


class DashboardTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user("admin", password="test-password-123")
        self.client.force_login(user)
        Alert.objects.create(ip_address="10.0.0.5", packet_size=1600, status="Suspicious")
        Alert.objects.create(ip_address="192.168.1.20", packet_size=200, status="Safe")

    def test_dashboard_lists_alerts(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["alerts"]), 2)
        self.assertEqual(len(response.context["line_labels"]), 7)

    def test_filter_by_ip(self):
        response = self.client.get(reverse("dashboard"), {"ip": "192.168"})
        ips = [a.ip_address for a in response.context["alerts"]]
        self.assertEqual(ips, ["192.168.1.20"])

    def test_filter_by_status(self):
        response = self.client.get(reverse("dashboard"), {"status": "Suspicious"})
        statuses = {a.status for a in response.context["alerts"]}
        self.assertEqual(statuses, {"Suspicious"})


class AlertActionTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user("admin", password="test-password-123")
        self.client.force_login(user)
        self.alert = Alert.objects.create(ip_address="10.0.0.5", packet_size=1600, status="Suspicious")

    def test_unblock_marks_alert_safe(self):
        response = self.client.get(reverse("unblock_alert", args=[self.alert.id]))
        self.assertRedirects(response, reverse("dashboard"))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, "Safe")

    def test_delete_removes_alert(self):
        response = self.client.get(reverse("delete_alert", args=[self.alert.id]))
        self.assertRedirects(response, reverse("dashboard"))
        self.assertFalse(Alert.objects.filter(id=self.alert.id).exists())

    def test_unknown_alert_returns_404(self):
        self.assertEqual(self.client.get(reverse("unblock_alert", args=[9999])).status_code, 404)


class ExportTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user("admin", password="test-password-123")
        self.client.force_login(user)
        Alert.objects.create(ip_address="10.0.0.5", packet_size=1600, status="Suspicious")

    def test_csv_export(self):
        response = self.client.get(reverse("export_csv"))
        self.assertEqual(response["Content-Type"], "text/csv")
        lines = response.content.decode().strip().splitlines()
        self.assertEqual(lines[0], "IP Address,Packet Size,Timestamp,Status")
        self.assertIn("10.0.0.5,1600", lines[1])

    def test_pdf_export(self):
        response = self.client.get(reverse("export_pdf"))
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF"))


class PacketClassificationTests(TestCase):
    """process_packet is the detection core: big packets are flagged and emailed."""

    def setUp(self):
        from scapy.all import IP, TCP, Raw  # imported here so the rest of the suite runs without scapy

        from . import packet_sniffer

        self.sniffer = packet_sniffer
        self.packet = lambda size: IP(src="10.0.0.5", dst="10.0.0.1") / TCP() / Raw(b"x" * size)
        self.threshold = packet_sniffer.THRESHOLD

    def test_large_packet_is_suspicious_and_sends_email(self):
        self.sniffer.process_packet(self.packet(self.threshold + 100))
        alert = Alert.objects.get()
        self.assertEqual(alert.status, "Suspicious")
        self.assertEqual(alert.ip_address, "10.0.0.5")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("10.0.0.5", mail.outbox[0].subject)

    def test_small_packet_is_safe_and_sends_no_email(self):
        self.sniffer.process_packet(self.packet(100))
        self.assertEqual(Alert.objects.get().status, "Safe")
        self.assertEqual(len(mail.outbox), 0)

    def test_non_ip_packet_is_ignored(self):
        from scapy.all import Ether

        self.sniffer.process_packet(Ether())
        self.assertEqual(Alert.objects.count(), 0)
