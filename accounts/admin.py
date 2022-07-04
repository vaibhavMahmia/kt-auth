from django.contrib import admin
from accounts.models import Customer, Dealer
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# Register your models here.

class CustomerAdmin(BaseUserAdmin):
    
    # The fields to be used in displaying the User model.
    # These override the definitions on the base CustomerAdmin
    # that reference specific fields on auth.User.
    list_display = ('id', 'email', 'name', 'is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        ('Customer  Credientials', {'fields': ('email', 'password',)}),
        ('Personal info', {'fields': ('kt_id', 'name','mobile', 'pincode', 'state', 'city', 'address', 'account_type', 'account_category', 'tc')}),
        ('Permissions', {'fields': ('is_admin','is_active','is_verified')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute.CustomerAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email','kt_id', 'name','mobile', 'pincode', 'state', 'city', 'address', 'account_type', 'account_category', 'tc', 'password1', 'password2','is_active','is_verified'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ()


# Now register the new UserAdmin...
admin.site.register(Customer, CustomerAdmin)
admin.site.register(Dealer)
