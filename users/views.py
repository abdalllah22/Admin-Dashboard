from rest_framework import viewsets, exceptions, status
from rest_framework.decorators import api_view
from rest_framework.views import APIView

from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import User, Permission, Role
from .serializers import UserSerializer, PermissionSerializer, RoleSerializer
from .authentication import generate_access_token, JWTAuthentication

# Create your views here.

@api_view(['POST'])
def register(request):
    data = request.data 

    if data['password'] != data['password_confirm']:
        raise exceptions.APIException('Password does not match!')
    
    serializer = UserSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    
    user = User.objects.filter(email=email).first()
    
    if user is None:
        raise exceptions.AuthenticationFailed('User not found')

    if not user.check_password(password):
        raise exceptions.AuthenticationFailed('Incorrect Password')

    response = Response()

    token = generate_access_token(user)
    response.set_cookie(key='jwt', value= token, httponly=True)
    response.data = {
        'jwt': token,
    }

    return response
    

@api_view(['POST'])
def logout(request):
    response = Response()
    response.delete_cookie(key='jwt')
    response.data = {
        'messages': 'Logged out success'
    }
    
    return response

class AuthenticatedUser(APIView):
    authentication_classes = [JWTAuthentication,]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        serializer = UserSerializer(request.user)
        return Response({
            'data': serializer.data
        })


class PermissionAPIView(APIView):
    authentication_classes = [JWTAuthentication,]
    permission_classes = [IsAuthenticated]
    
    def get(self,request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response({
            'data': serializer.data
        })    

class RoleViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication,]
    permission_classes = [IsAuthenticated]
    
    def list(self,request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)

    def create(self,request):
        serializer = RoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)

    def retrieve(self,request, pk=None):
        role = Role.objects.get(id=pk)
        serializer = RoleSerializer(role)

        return Response({
            'data': serializer.data
        })

    
    def update(self,request, pk=None):
        role = Role.objects.get(id=pk)
        serializer = RoleSerializer(instance=role, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'data': serializer.data
        }, status=status.HTTP_202_ACCEPTED)

    def destroy(self,request, pk=None):
        role = Role.objects.get(id=pk)
        role.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)