import asyncio
import sys
from pathlib import Path
from sqlalchemy import select

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.security import hash_password
from app.database.session import AsyncSessionLocal
from app.models.user import User, UserRole


async def main() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == "admin@sentinel.local"))
        if result.scalar_one_or_none():
            print("Admin already exists")
            return
        db.add(
            User(
                email="admin@sentinel.local",
                full_name="Sentinel Admin",
                hashed_password=hash_password("ChangeMe123!"),
                role=UserRole.ADMIN,
            )
        )
        await db.commit()
        print("Created admin@sentinel.local with password ChangeMe123!")


if __name__ == "__main__":
    asyncio.run(main())
