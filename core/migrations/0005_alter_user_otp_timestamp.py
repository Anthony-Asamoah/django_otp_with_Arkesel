# Generated by Django 4.1.1 on 2022-10-27 15:41

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_alter_user_otp_timestamp_arkeselsmsdevice'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='otp_timestamp',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 27, 15, 41, 28, 435841)),
        ),
    ]