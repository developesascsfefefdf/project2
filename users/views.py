from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings  # Import settings
from users.models import MyUser
from users.forms import UserCreateForm, UserUpdateForm, CustomerUpdateForm, CustomerProfileForm, CustomPasswordResetForm
from django.contrib.auth.views import PasswordResetView, LogoutView
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.views import PasswordResetConfirmView
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from django.core.mail import send_mail
from django.urls import reverse
from django.shortcuts import redirect
from django.views.generic.edit import FormView
from .forms import InviteUserForm
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from users.forms import InviteUserForm
from users.models import MyUser
from users.token_generator import custom_token_generator 
from django.db import IntegrityError

class MyMixin(LoginRequiredMixin, UserPassesTestMixin):
    """ Mixin for Authentication and User is Admin or not """
    def test_func(self):
        return self.request.user.user_type == 'admin'

class InviteUserView(MyMixin, FormView):
    form_class = InviteUserForm
    template_name = 'users/invite.html'
    token_generator = PasswordResetTokenGenerator()
    
    def form_valid(self, form):
        email = form.cleaned_data['email']
        user_type = form.cleaned_data['user_type']
        
        try:
            user, created = MyUser.objects.get_or_create(
                email=email,
                defaults={'user_type': user_type, 'username': self.generate_unique_username(email)}
            )
        except IntegrityError:
            messages.error(self.request, f"A user with the email {email} already exists.")
            return redirect(reverse('user_app:invite'))

        if not created:
            messages.error(self.request, f"A user with the email {email} already exists.")
            return redirect(reverse('user_app:invite'))
        
        token = self.token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        register_url = self.request.build_absolute_uri(
    reverse('user_app:register') + f'?uid={uid}&token={token}&user_type={user_type}'
)
        
        send_mail(
            'Invite to Register',
            f'Please register using the following link: {register_url}\nUser Type: {user_type}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        
        messages.success(self.request, f'Invitation sent to {email}.')
        return redirect(reverse('user_app:invite'))

    def generate_unique_username(self, email):
        base_username = email.split('@')[0]
        unique_username = base_username
        counter = 1
        while MyUser.objects.filter(username=unique_username).exists():
            unique_username = f"{base_username}_{counter}"
            counter += 1
        return unique_username


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'
    success_url = reverse_lazy('user_app:password_reset_complete')
    form_class = SetPasswordForm

    def form_valid(self, form):
        # Save the new password
        user = form.save()
        messages.success(self.request, 'Your password has been changed successfully. Please log in.')
        return super().form_valid(form)




class CustomLogoutView(LogoutView):
    def get_next_page(self):
        return reverse_lazy('user_app:home') 

class CustomPasswordResetView(PasswordResetView):
    form_class = CustomPasswordResetForm
    email_template_name = 'users/password_reset_email.html'
    html_email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject.txt'
    success_url = reverse_lazy('user_app:password_reset_done')
    template_name = 'users/password_reset.html'

class MyMixin(LoginRequiredMixin, UserPassesTestMixin):
    """ Mixin for Authentication and User is Admin or not """
    def test_func(self):
        return self.request.user.user_type == 'admin'

@login_required()
def home(request):
    """ Home Page """
    admin_count = MyUser.objects.filter(user_type='admin').count()
    customer_count = MyUser.objects.filter(user_type='customer').count()
    context = {
        'a_count': admin_count,
        'c_count': customer_count,
    }
    return render(request, 'users/home.html', context)


class UserRegistrationView(CreateView):
    model = MyUser
    form_class = UserCreateForm
    template_name = 'users/register.html'
    success_url = reverse_lazy('user_app:home')
    token_generator = custom_token_generator

    def get(self, request, *args, **kwargs):
        uidb64 = request.GET.get('uid')
        token = request.GET.get('token')
        user_type = request.GET.get('user_type')

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = MyUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, MyUser.DoesNotExist):
            user = None

        if user is not None and self.token_generator.check_token(user, token):
            # Token is valid
            return super().get(request, *args, **kwargs)
        else:
            messages.error(request, 'The invitation link is invalid or has expired.')
            return redirect(reverse_lazy('user_app:invite'))

    def form_valid(self, form):
        user = form.save(commit=False)
        user_type = self.request.GET.get('user_type')
        user.user_type = user_type  # Assign user type from URL
        password = form.cleaned_data.get('password')
        if password:
            user.set_password(password)  # Hash the password
        user.save()
        messages.success(self.request, f"{user.username} is created successfully!")
        return redirect(self.success_url)


class UserListView(MyMixin, ListView):
    """ List of Users for Admin """
    model = MyUser
    template_name = 'users/list.html'
    context_object_name = 'data'
    

   


class UserCreateView(MyMixin, CreateView):
    """ Create a new User by Admin """
    model = MyUser
    form_class = UserCreateForm
    template_name = 'users/create.html'
    success_url = reverse_lazy('user_app:list')

    def form_valid(self, form):
        user = form.save(commit=False)
        password = form.cleaned_data['password']
        user.set_password(password)
        messages.success(self.request, f"{user.username} is created successfully!")
        user.save()
        return redirect(reverse_lazy('user_app:list'))

class UserUpdateView(MyMixin, UpdateView):
    """ Update a user by Admin """
    model = MyUser
    form_class = UserUpdateForm
    template_name = 'users/update.html'
    success_url = reverse_lazy('user_app:list')

    def form_valid(self, form):
        super(UserUpdateView, self).form_valid(form)
        messages.success(self.request, f"user is updated successfully!")
        return redirect(reverse_lazy('user_app:list'))

class UserDeleteView(MyMixin, DeleteView):
    """ Delete a user by Admin """
    model = MyUser
    template_name = 'users/delete.html'
    success_url = reverse_lazy('user_app:list')

    def form_valid(self, form):
        super(UserDeleteView, self).form_valid(form)
        messages.warning(self.request, f"user is deleted successfully!")
        return redirect(reverse_lazy('user_app:list'))

class UserProfile(LoginRequiredMixin, UpdateView):
    """ All User Profile Page """
    def get(self, request, **kwargs):
        user = request.user
        data = MyUser.objects.get(id=user.id)
        c_form = CustomerUpdateForm(instance=user)
        p_form = CustomerProfileForm(instance=user.profile)

        context = {
            'data': data,
            'c_form': c_form,
            'p_form': p_form,
        }
        return render(request, 'users/profile.html', context)

    def post(self, request, *args, **kwargs):
        user = request.user
        c_form = CustomerUpdateForm(request.POST, instance=user)
        p_form = CustomerProfileForm(request.POST, request.FILES, instance=user.profile)
        if c_form.is_valid() and p_form.is_valid():
            username = c_form.cleaned_data['username']
            c_form.save()
            p_form.save()
            messages.success(request, f"{username}'s profile has been updated successfully!")
        return redirect(reverse_lazy('user_app:profile', kwargs={'pk': user.id}))
