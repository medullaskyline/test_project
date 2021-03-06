from django.contrib import admin
from testing_app.models import Category, Page, UserProfile, CredentialsModel


class PageAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'url')


class CategoryAdmin(admin.ModelAdmin):
    prepopulated_fields = {'slug': ('name',)}

class CredentialsModelAdmin(admin.ModelAdmin):
    list_display = ('id', 'credential')

admin.site.register(Category, CategoryAdmin)
admin.site.register(Page, PageAdmin)
admin.site.register(UserProfile)
admin.site.register(CredentialsModel, CredentialsModelAdmin)