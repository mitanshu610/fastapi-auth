from passlib.context import CryptContext
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from auth.models import User


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_password_hash(password):
    return pwd_context.hash(password)


async def authenticate_user(db: AsyncSession, email: str, password: str):
    user = await db.execute(select(User).where(User.email == email))
    user = user.scalars().first()
    if not user or not await verify_password(password, user.hashed_password):
        return False
    return user
