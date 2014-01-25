from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import render_to_response, render
from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.forms import ValidationError
from django.core.urlresolvers import reverse

from allauth.utils import get_user_model
from allauth.account.utils import (perform_login, complete_signup,
                                   user_username)
from allauth.account import app_settings as account_settings
from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.exceptions import ImmediateHttpResponse

from .models import SocialLogin
from . import app_settings
from . import signals
from .adapter import get_adapter

User = get_user_model()


def _process_signup(request, sociallogin):
    auto_signup = get_adapter().is_auto_signup_allowed(request,
                                                       sociallogin)
    if not auto_signup:
        request.session['socialaccount_sociallogin'] = sociallogin.serialize()
        url = reverse('socialaccount_signup')
        ret = HttpResponseRedirect(url)
    else:
        # Ok, auto signup it is, at least the e-mail address is ok.
        # We still need to check the username though...
        if account_settings.USER_MODEL_USERNAME_FIELD:
            username = user_username(sociallogin.account.user)
            try:
                get_account_adapter().clean_username(username)
            except ValidationError:
                # This username is no good ...
                user_username(sociallogin.account.user, '')
        # FIXME: This part contains a lot of duplication of logic
        # ("closed" rendering, create user, send email, in active
        # etc..)
        try:
            if not get_adapter().is_open_for_signup(request,
                                                    sociallogin):
                return render(request,
                              "account/signup_closed.html")
        except ImmediateHttpResponse as e:
            return e.response
        get_adapter().save_user(request, sociallogin, form=None)
        ret = complete_social_signup(request, sociallogin)
    return ret


def _login_social_account(request, sociallogin):
    return perform_login(request, sociallogin.account.user,
                         email_verification=app_settings.EMAIL_VERIFICATION,
                         redirect_url=sociallogin.get_redirect_url(request),
                         signal_kwargs={"sociallogin": sociallogin})


def render_authentication_error(request, extra_context={}):
    return render_to_response(
        "socialaccount/authentication_error.html",
        extra_context, context_instance=RequestContext(request))

def is_trusted_email(email):
    is_trusted = False
    trusted_domains = app_settings.TRUSTED_EMAIL_DOMAINS

    if email is not None and len(trusted_domains) > 0:
        # Extract the domain name from the e-mail address
        match = re.search("@[\w.]+", email)

        if match:
            domain = match.group(0)[1:]
            if domain in trusted_domains:
                is_trusted = True

    return is_trusted

def _add_social_account(request, sociallogin):
    if request.user.is_anonymous():
        # This should not happen. Simply redirect to the connections
        # view (which has a login required)
        return HttpResponseRedirect(reverse('socialaccount_connections'))
    level = messages.INFO
    message = 'socialaccount/messages/account_connected.txt'
    if sociallogin.is_existing:
        if sociallogin.account.user != request.user:
            # Social account of other user. For now, this scenario
            # is not supported. Issue is that one cannot simply
            # remove the social account from the other user, as
            # that may render the account unusable.
            level = messages.ERROR
            message = 'socialaccount/messages/account_connected_other.txt'
        else:
            # This account is already connected -- let's play along
            # and render the standard "account connected" message
            # without actually doing anything.
            pass
    else:
        # New account, let's connect
        sociallogin.connect(request, request.user)
        try:
            signals.social_account_added.send(sender=SocialLogin,
                                              request=request,
                                              sociallogin=sociallogin)
        except ImmediateHttpResponse as e:
            return e.response
    default_next = get_adapter() \
        .get_connect_redirect_url(request,
                                  sociallogin.account)
    next_url = sociallogin.get_redirect_url(request) or default_next
    get_account_adapter().add_message(request, level, message)
    return HttpResponseRedirect(next_url)


def complete_social_login(request, sociallogin):
    assert not sociallogin.is_existing
    login_exists = sociallogin.lookup()

    try:
        get_adapter().pre_social_login(request, sociallogin)
        signals.pre_social_login.send(sender=SocialLogin,
                                      request=request,
                                      sociallogin=sociallogin)
    except ImmediateHttpResponse as e:
        return e.response

    # If the social login did not exist but we trust the domain from which the
    # e-mail address was sent, then lookup the user associated with that
    # address and use it if exists.  This allows the system to be accessed from
    # different URLs.
    if not login_exists and is_trusted_email(sociallogin.account.user.email):
        # Nothing in the Django user model says that e-mail addresses have to
        # be unique.  If there are duplicate entries, use the one that has the
        # smallest primary key.
        users = User.objects.filter(
            email__iexact=sociallogin.account.user.email).order_by('pk')

        if len(users):
            user = users[0]
            sociallogin.account.user = user
            sociallogin.save()

            if len(users) > 1:
                import warnings
                warnings.warn(
                    "Duplicate e-mail accounts dedicated in Django Users model. "
                    "Picking user name %s" % user.username)

    if request.user.is_authenticated():
        if sociallogin.is_existing:
            # Existing social account, existing user
            if sociallogin.account.user != request.user:
                # Social account of other user. Simply logging in may
                # not be correct in the case that the user was
                # attempting to hook up another social account to his
                # existing user account. For now, this scenario is not
                # supported. Issue is that one cannot simply remove
                # the social account from the other user, as that may
                # render the account unusable.
                pass
            ret = _login_social_account(request, sociallogin)
        else:
            # New social account
            sociallogin.account.user = request.user
            sociallogin.save()
            default_next = reverse('socialaccount_connections')
            next = sociallogin.get_redirect_url(request,
                                                fallback=default_next)
            messages.add_message(request, messages.INFO,
                                 _('The social account has been connected'))
            return HttpResponseRedirect(next)

    if sociallogin.state.get('process') == 'connect':
        return _add_social_account(request, sociallogin)
    else:
        return _complete_social_login(request, sociallogin)


def _complete_social_login(request, sociallogin):
    if request.user.is_authenticated():
        logout(request)
    if sociallogin.is_existing:
        # Login existing user
        ret = _login_social_account(request, sociallogin)
    else:
        # New social user
        ret = _process_signup(request, sociallogin)
    return ret


def complete_social_signup(request, sociallogin):
    return complete_signup(request,
                           sociallogin.account.user,
                           app_settings.EMAIL_VERIFICATION,
                           sociallogin.get_redirect_url(request),
                           signal_kwargs={'sociallogin': sociallogin})


# TODO: Factor out callable importing functionality
# See: account.utils.user_display
def import_path(path):
    modname, _, attr = path.rpartition('.')
    m = __import__(modname, fromlist=[attr])
    return getattr(m, attr)
