# Generated by Django 5.1.8 on 2025-04-16 06:49

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0069_project_purl'),
    ]

    operations = [
        migrations.AddField(
            model_name='discovereddependency',
            name='uuid',
            field=models.UUIDField(null=True, editable=False, verbose_name='UUID'),
        ),
    ]
