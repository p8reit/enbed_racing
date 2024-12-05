from allianceauth import hooks
from allianceauth.services.hooks import MenuItemHook, UrlHook
from . import urls  # Ensure this imports your urls.py

class EmbedRacingMenu(MenuItemHook):
    def __init__(self):
        # The menu item hook for Embed Racing
        super().__init__(
            'Embed Racing',
            'fas fa-flag-checkered fa-fw',  # Icon for the menu item
            'embed_racing:dashboard',  # Namespace and view name
            navactive=['embed_racing:']
        )

    def render(self, request):
        if request.user.has_perm('embed_racing.view_trackedrequest'):
            return super().render(request)
        return ''

@hooks.register('menu_item_hook')
def register_menu():
    return EmbedRacingMenu()

@hooks.register('url_hook')
def register_url():
    # Ensure the URL hook properly uses the app_name and namespace
    return UrlHook((urls.urlpatterns, 'embed_racing'), 'embed_racing', '^embed_racing/')
