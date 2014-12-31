# coding=utf-8
from __future__ import print_function

from jinja2 import Environment, PackageLoader

from . import views
from .constants import TEMPLATES


def_loader = PackageLoader('authcode', 'templates')
def_env = Environment(loader=def_loader)


class ViewsMixin(object):

    def auth_sign_in(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.sign_in(self, request, self.session, *args, **kwargs)

    def auth_sign_out(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.sign_out(self, request, **kwargs)

    def auth_reset_password(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.reset_password(self, request, **kwargs)

    def auth_change_password(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.change_password(self, request, **kwargs)

    def render_template(self, name, **kwargs):
        """Search for a setting named ``template_<name>`` and renders it.
        If one is not defined it uses the default template of the library
        at ``autchode/templates/<name>,html``.

        To render the template uses the ``render`` function, a property that
        has been probably overwritten in a ``auth.setup_for_something``
        function (eg. ``setup_for_flask``).
        """
        custom_template = getattr(self, 'template_' + name)
        if custom_template:
            return self.render(custom_template, **kwargs)
        template = TEMPLATES.get(name)
        return self.default_render(template, **kwargs)

    def default_render(self, template, **kwargs):
        tmpl = def_env.get_template(template)
        return tmpl.render(kwargs)

    def render(self, template, **kwargs):
        """Should be overwritten in the setup"""
        return self.default_render(template, **kwargs)  # pragma: no cover

    def send_email(self, user, subject, msg):
        """Should be overwritten in the setup"""
        print('To:', user)
        print('Subject:', subject)
        print(msg)
