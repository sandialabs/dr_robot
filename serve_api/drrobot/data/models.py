from django.db import models

class Data(models.Model):
    domainid = models.IntegerField(primary_key=True)
    ip = models.CharField(max_length=100, blank=True, null=True)
    hostname = models.CharField(max_length=100, blank=True, null=True)
    http_headers = models.TextField(blank=True, null=True)
    https_headers = models.TextField(blank=True, null=True)
    domain = models.ForeignKey('Domains', models.DO_NOTHING, db_column='domain', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'data'


class Domains(models.Model):
    domain = models.CharField(primary_key=True, max_length=100, blank=True)

    class Meta:
        managed = False
        db_table = 'domains'
