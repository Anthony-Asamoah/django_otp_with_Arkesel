# Generated by Django 4.1.2 on 2022-10-28 13:29

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_alter_user_id'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='name',
            new_name='user',
        ),
    ]
