from django.dispatch import receiver
from django.db.models.signals import post_save

from users.models import MyUser, Profile

# Example signal handler without Tools.demo.mcast.sender
@receiver(post_save, sender=MyUser)
def create_profile(instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=MyUser)
def save_profile(instance, **kwargs):
    instance.profile.save()
