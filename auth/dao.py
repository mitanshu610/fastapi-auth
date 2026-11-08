from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional

from auth.models import User, RefreshToken
from utils.encryption import DataEncryptor  # Assuming DataEncryptor is in utils
from utils.custom_logger import logger


class UserDAO:
    def __init__(self, db: AsyncSession, encryptor: Optional[DataEncryptor] = None):
        self.encryptor = encryptor
        self.db = db

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Fetches a user by their ID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalars().first()

    async def get_user_by_email(self, plain_email: str) -> Optional[User]:
        """
        Fetches a user by their PLAINTEXT email.
        The email will be encrypted before querying the database.
        """
        encrypted_email = await self.encryptor.encrypt(plain_email)
        result = await self.db.execute(select(User).where(User.email == encrypted_email))
        return result.scalars().first()

    async def get_user_by_encrypted_email(self, encrypted_email: str) -> Optional[User]:
        """
        Fetches a user by their ENCRYPTED email.
        """
        result = await self.db.execute(select(User).where(User.email == encrypted_email))
        return result.scalars().first()


class AuthDAO:
    """Data Access Object for authentication operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        try:
            result = await self.db.execute(select(User).where(User.email == email))
            return result.scalars().first()
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {str(e)}")
            raise

    async def create_user(self, user_data: dict) -> User:
        """Create a new user"""
        try:
            db_user = User(**user_data)
            self.db.add(db_user)
            await self.db.commit()
            await self.db.refresh(db_user)
            return db_user
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            await self.db.rollback()
            raise

    async def get_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Get refresh token from database"""
        try:
            result = await self.db.execute(
                select(RefreshToken).where(RefreshToken.token == token)
            )
            return result.scalars().first()
        except Exception as e:
            logger.error(f"Error getting refresh token: {str(e)}")
            raise

    async def delete_refresh_token(self, token: str) -> bool:
        """Delete refresh token from database"""
        try:
            refresh_token = await self.get_refresh_token(token)
            if refresh_token:
                await self.db.delete(refresh_token)
                await self.db.commit()
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting refresh token: {str(e)}")
            await self.db.rollback()
            raise
