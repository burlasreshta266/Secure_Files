from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mainapp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='biometric_phrase',
            field=models.CharField(default='securefiles2026', max_length=64),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='user',
            name='biometric_secret',
            field=models.TextField(default='securefiles2026'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='user',
            name='failed_login_attempts',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='user',
            name='lockout_until',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
