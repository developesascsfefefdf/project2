from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy, reverse
from django.views.generic import ListView, CreateView, UpdateView, DeleteView, FormView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.utils.safestring import mark_safe
from django.core.mail import send_mail

from users.models import MyUser
from users.forms import UserCreateForm, UserUpdateForm, CustomerUpdateForm, CustomerProfileForm, CustomPasswordResetForm, InviteUserForm
from django.contrib.auth.views import PasswordResetView, LogoutView, PasswordResetConfirmView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from .utils import generate_invite_token
from django.contrib.auth.forms import SetPasswordForm


class MyMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Mixin for Authentication and User is Admin or not."""
    def test_func(self):
        return self.request.user.user_type == 'admin'

class InviteUserView(MyMixin, FormView):
    form_class = InviteUserForm
    template_name = 'users/invite.html'

    def form_valid(self, form):
        email = form.cleaned_data['email']
        user_type = form.cleaned_data['user_type']
        
        # Generate token and registration link
        token = generate_invite_token(email, user_type)
        register_url = self.request.build_absolute_uri(reverse('user_app:register')) + f'?token={token}'
        
        # Send invitation email
        send_mail(
            'Invite to Register',
            f'Please register using the following link: {register_url}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        
        messages.success(self.request, f'Invitation sent to {email}.')
        return redirect(reverse('user_app:invite'))

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'
    success_url = reverse_lazy('user_app:password_reset_complete')
    form_class = SetPasswordForm

    def form_valid(self, form):
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

@login_required
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

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        token = request.GET.get('token')
        if not token:
            messages.error(request, 'Invalid registration link.')
            return redirect(reverse_lazy('user_app:invite'))

        try:
            # Decode the token
            access_token = AccessToken(token)
            email = access_token['email']
            user_type = access_token['user_type']
            
            # Store email and user_type in session
            request.session['email'] = email
            request.session['user_type'] = user_type
            
            if user_type not in ['admin', 'customer']:
                messages.error(request, 'Invalid user type.')
                return redirect(reverse_lazy('user_app:invite'))
                
        except TokenError:
            messages.error(request, 'Invalid or expired registration link.')
            return redirect(reverse_lazy('user_app:invite'))

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password'])
        
        email = self.request.session.get('email')
        user_type = self.request.session.get('user_type')
        
        if email and user_type:
            user.email = email
            user.user_type = user_type
        else:
            messages.error(self.request, 'Session data missing. Please try again.')
            return redirect(reverse_lazy('user_app:invite'))
        
        user.save()
        messages.success(self.request, mark_safe(f"<strong>{user.username}</strong> is created successfully!"))
        return redirect(self.success_url)

class UserListView(MyMixin, ListView):
    model = MyUser
    template_name = 'users/list.html'
    context_object_name = 'data'

class UserCreateView(MyMixin, CreateView):
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
    model = MyUser
    form_class = UserUpdateForm
    template_name = 'users/update.html'
    success_url = reverse_lazy('user_app:list')

    def form_valid(self, form):
        super(UserUpdateView, self).form_valid(form)
        messages.success(self.request, "User is updated successfully!")
        return redirect(reverse_lazy('user_app:list'))

class UserDeleteView(MyMixin, DeleteView):
    model = MyUser
    template_name = 'users/delete.html'
    success_url = reverse_lazy('user_app:list')

    def form_valid(self, form):
        super(UserDeleteView, self).form_valid(form)
        messages.warning(self.request, "User is deleted successfully!")
        return redirect(reverse_lazy('user_app:list'))

class UserProfile(LoginRequiredMixin, UpdateView):
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
