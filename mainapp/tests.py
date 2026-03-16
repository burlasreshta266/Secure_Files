import json

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import User


class AuthFlowTests(TestCase):
    def _timestamps_for_phrase(self, phrase, *, start=1000, dwell=80, flight=50):
        ts = []
        cursor = start
        for ch in phrase:
            dt = cursor
            ut = dt + dwell
            ts.append({'key': ch, 'dt': dt, 'ut': ut})
            cursor = ut + flight
        return ts

    def _enroll(self, username='alice', phrase='myphrase2026'):
        ts1 = self._timestamps_for_phrase(phrase, start=1000)
        ts2 = self._timestamps_for_phrase(phrase, start=3000)
        return self.client.post(
            reverse('enroll'),
            {
                'username': username,
                'biometric_phrase': phrase,
                'biometric_1': phrase,
                'timestamps_1': json.dumps(ts1),
                'biometric_2': phrase,
                'timestamps_2': json.dumps(ts2),
            },
        )

    def test_enroll_fails_with_wrong_phrase(self):
        phrase = 'myphrase2026'
        ts1 = self._timestamps_for_phrase(phrase)
        ts2 = self._timestamps_for_phrase(phrase, start=3000)

        response = self.client.post(
            reverse('enroll'),
            {
                'username': 'bob',
                'biometric_phrase': phrase,
                'biometric_1': 'wrong',
                'timestamps_1': json.dumps(ts1),
                'biometric_2': phrase,
                'timestamps_2': json.dumps(ts2),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(username='bob').exists())

    def test_failed_biometric_attempts_trigger_lockout(self):
        self._enroll()
        user = User.objects.get(username='alice')
        bad_ts = self._timestamps_for_phrase('nottherightphrase')

        for _ in range(5):
            self.client.post(
                reverse('login'),
                {
                    'username': 'alice',
                    'biometric': 'nottherightphrase',
                    'timestamps': json.dumps(bad_ts),
                },
            )

        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertIsNotNone(user.lockout_until)
        self.assertGreater(user.lockout_until, timezone.now())

    def test_biometric_login_succeeds(self):
        phrase = 'myphrase2026'
        self._enroll(phrase=phrase)
        ts = self._timestamps_for_phrase(phrase)

        response = self.client.post(
            reverse('login'),
            {
                'username': 'alice',
                'biometric': phrase,
                'timestamps': json.dumps(ts),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

        user = User.objects.get(username='alice')
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNone(user.lockout_until)
        self.assertFalse(user.has_usable_password())
