from rest_framework import serializers

from .models import User



class UserSerializer(serializers.ModelSerializer):
    # confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name','email' ,'password']
        extra_kwargs = {
            'password': {
                'write_only':True,
                # 'style': {'input_type':'password'}
            }
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance 